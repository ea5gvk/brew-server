//! Server-to-server federation: connects this brew-server out to configured
//! peer brew-server instances over the *same* Brew WebSocket protocol real
//! Basestations use -- a peer link authenticates and upgrades exactly like a
//! Basestation would, just tagged `X-Brew-Mode: Peer` (see
//! `state::ClientMode::Peer`).
//!
//! Once connected, a peer is registered in `AppState.inner.clients` like any
//! other connection, and `router::handle_packet` processes whatever it sends
//! completely normally. That is deliberate: it means private/group call
//! routing and SDS routing need *no* federation-specific code at all -- they
//! already resolve a destination via `inner.subscribers`/`inner.group_clients`
//! and forward raw bytes to whatever `ClientId` owns it, peer or not. The one
//! piece that genuinely is federation-specific is registration propagation
//! (see `router::handle_subscriber`'s relay-to-other-peers step) and the
//! full-table sync a newly connected peer needs (`sync_peer` below), since a
//! peer link only sees registration *events* going forward otherwise.
//!
//! This module owns the *outbound* half (dialing peers configured in
//! `[[federation.peers]]`). The inbound half needs no special code: an
//! incoming peer connection is just another `server::client_session`
//! WebSocket upgrade, same as a Basestation, differing only in the
//! `X-Brew-Mode: Peer` header it sends.

use crate::config::FederationPeerConfig;
use crate::protocol::{self, ConnVersion};
use crate::state::{AppState, Client, ClientMode};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

/// Spawns one reconnecting dial loop per enabled `[[federation.peers]]`
/// entry. No-op when federation is disabled.
pub async fn run(state: Arc<AppState>) {
    if !state.config.federation.enabled {
        return;
    }
    for peer in state.config.federation.peers.clone() {
        if !peer.enabled {
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move { peer_loop(state, peer).await });
    }
}

async fn peer_loop(state: Arc<AppState>, peer: FederationPeerConfig) {
    let interval = Duration::from_secs(peer.reconnect_interval_seconds.max(5));
    loop {
        info!(peer = %peer.name, remote_host = %peer.remote_host, "federation: connecting to peer");
        if let Err(e) = connect_and_run(&state, &peer).await {
            warn!(peer = %peer.name, error = %e, "federation: peer link failed");
        }
        tokio::time::sleep(interval).await;
    }
}

/// Minimal parsed HTTP/1.1 response: just enough to drive the Brew discovery
/// digest dance (status, headers, body), not a general-purpose HTTP client.
struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// `User-Agent` this server identifies itself with when dialling a peer.
const USER_AGENT: &str = concat!("brew-server/", env!("CARGO_PKG_VERSION"));

/// Sends one plain (non-upgrade) `GET`, closes the connection after reading
/// the response. Used only for the discovery/digest pre-flight -- the actual
/// WebSocket upgrade is a separate connection via `tokio_tungstenite`.
///
/// Every request -- the unauthenticated first one and the digest retry alike
/// -- announces `X-Brew-Mode: Peer` and `X-Brew-Version`, the way a
/// Basestation announces its own mode on discovery. That matters: with
/// `[auth]` enabled, the far end records the mode of the *authorized*
/// discovery request in the session token and ignores whatever the upgrade
/// says, so without them this link used to be registered over there as a
/// Basestation (no table sync, no relay) and federation only worked in one
/// direction. Some Brew servers also refuse a discovery without a
/// `User-Agent` (400).
async fn http_get(remote_host: &str, path: &str, authorization: Option<&str>) -> anyhow::Result<HttpResponse> {
    let mut stream = TcpStream::connect(remote_host).await?;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {remote_host}\r\nUser-Agent: {USER_AGENT}\r\nX-Brew-Mode: Peer\r\nX-Brew-Version: {}\r\nConnection: close\r\n",
        protocol::BREW_PROTOCOL_VERSION,
    );
    if let Some(a) = authorization {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    parse_http_response(&buf)
}

fn parse_http_response(buf: &[u8]) -> anyhow::Result<HttpResponse> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response (no header/body split)"))?;
    let header_text = std::str::from_utf8(&buf[..split])?;
    let body = buf[split + 4..].to_vec();
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow::anyhow!("empty HTTP response"))?;
    let status = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("bad HTTP status line: {status_line}"))?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok(HttpResponse { status, headers, body })
}

/// Runs the Brew discovery flow (the same 401-challenge-then-session-token
/// dance a real Basestation performs, or a single request when the peer has
/// `[auth]` disabled) and returns the path to actually upgrade the WebSocket
/// at.
async fn discover(peer: &FederationPeerConfig, path: &str) -> anyhow::Result<String> {
    let resp = http_get(&peer.remote_host, path, None).await?;
    match resp.status {
        200 => Ok(String::from_utf8(resp.body)?.trim().to_string()),
        401 => {
            let challenge_hdr = resp.headers.get("www-authenticate")
                .ok_or_else(|| anyhow::anyhow!("401 with no WWW-Authenticate"))?;
            let challenge = crate::sip::auth::parse_params(challenge_hdr);
            let cnonce = uuid::Uuid::new_v4().simple().to_string();
            let authz = crate::sip::auth::build_authorization(
                &challenge, &peer.username, &peer.password, "GET", path, &cnonce, 1,
            );
            let resp2 = http_get(&peer.remote_host, path, Some(&authz)).await?;
            if resp2.status != 200 {
                anyhow::bail!("digest auth rejected (HTTP {})", resp2.status);
            }
            Ok(String::from_utf8(resp2.body)?.trim().to_string())
        }
        other => anyhow::bail!("unexpected discovery status {other}"),
    }
}

async fn connect_and_run(state: &Arc<AppState>, peer: &FederationPeerConfig) -> anyhow::Result<()> {
    let path = normalize_path(&peer.path);
    let ws_path = discover(peer, &path).await?;

    let remote_addr = tokio::net::lookup_host(&peer.remote_host).await.ok()
        .and_then(|mut it| it.next());

    let ws_url = format!("ws://{}{}", peer.remote_host, normalize_path(&ws_path));
    let mut request = ws_url.into_client_request()?;
    request.headers_mut().insert("User-Agent", USER_AGENT.parse()?);
    // Also on the upgrade, not just discovery: a peer with `[auth]` disabled
    // takes the mode straight from the upgrade request.
    request.headers_mut().insert("X-Brew-Mode", "Peer".parse()?);
    request.headers_mut().insert("X-Brew-Version", protocol::BREW_PROTOCOL_VERSION.to_string().parse()?);
    request.headers_mut().insert("Sec-WebSocket-Protocol", "brew".parse()?);

    let (ws_stream, _resp) = tokio_tungstenite::connect_async(request).await?;
    info!(peer = %peer.name, "federation: peer link established");
    run_peer_session(state.clone(), peer.clone(), ws_stream, remote_addr).await;
    Ok(())
}

fn normalize_path(path: &str) -> String {
    let mut p = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    while p.len() > 1 && p.ends_with('/') { p.pop(); }
    p
}

/// Runs one established peer session: registers the peer in `inner.clients`
/// (mode `Peer`), sends it a full snapshot of everything this server
/// currently knows (see `sync_peer`), then pumps inbound frames through the
/// normal router and outbound frames from its `tx` queue -- the same shape
/// as `server::client_session`, just over a `tokio_tungstenite` client
/// socket instead of axum's server-side one.
async fn run_peer_session(
    state: Arc<AppState>,
    peer: FederationPeerConfig,
    ws_stream: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    remote_addr: Option<SocketAddr>,
) {
    let id = uuid::Uuid::new_v4();
    let (mut ws_tx, mut ws_rx) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let connected_at_ms = crate::telemetry::now_ms();
    state.inner.write().await.clients.insert(id, Client {
        tx: tx.clone(), mode: ClientMode::Peer, version: ConnVersion::V1, remote_addr, connected_at_ms, username: None,
    });
    info!(%id, peer = %peer.name, "federation: peer registered");

    sync_peer(&state, &tx).await;

    let writer = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if ws_tx.send(Message::Binary(packet.into())).await.is_err() { break; }
        }
    });

    while let Some(item) = ws_rx.next().await {
        match item {
            Ok(Message::Binary(data)) => crate::router::handle_packet(state.clone(), id, data.to_vec()).await,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            Ok(Message::Close(_)) => break,
            Ok(Message::Text(_)) | Ok(Message::Frame(_)) => {}
            Err(e) => { warn!(%id, peer = %peer.name, error = %e, "federation: peer link read error"); break; }
        }
    }

    writer.abort();
    state.cleanup_client(id).await;
    info!(%id, peer = %peer.name, "federation: peer link closed");
}

/// Sends a newly connected peer everything this server currently knows:
/// every registered ISSI (`SUB_REGISTER`) and its group affiliations
/// (`SUB_AFFILIATE`), regardless of whether this server learned them locally
/// or from another peer (transit). Without this, a peer only ever learns
/// about registrations that happen to change *after* it connects, so a
/// freshly (re)started link would be blind to everything already in place.
pub async fn sync_peer(state: &Arc<AppState>, tx: &mpsc::UnboundedSender<Vec<u8>>) {
    let snapshot: Vec<(u32, Vec<u32>)> = {
        let inner = state.inner.read().await;
        inner.subscribers.iter().map(|(issi, s)| (*issi, s.groups.iter().copied().collect())).collect()
    };
    for (issi, groups) in snapshot {
        let _ = tx.send(protocol::build_subscriber_message(protocol::SUB_REGISTER, issi, &[]));
        if !groups.is_empty() {
            let _ = tx.send(protocol::build_subscriber_message(protocol::SUB_AFFILIATE, issi, &groups));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Loopback HTTP server: answers one connection per entry of `responses`,
    /// in order, and returns the request head each connection sent.
    async fn http_stub(responses: Vec<&'static str>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut chunk = [0u8; 1024];
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 { break; }
                    buf.extend_from_slice(&chunk[..n]);
                }
                requests.push(String::from_utf8(buf).unwrap());
                sock.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (addr, handle)
    }

    fn assert_identifies_as_peer(request: &str) {
        let expected_ua = format!("User-Agent: brew-server/{}\r\n", env!("CARGO_PKG_VERSION"));
        assert!(request.contains(&expected_ua), "no User-Agent in {request:?}");
        assert!(request.contains("X-Brew-Mode: Peer\r\n"), "no X-Brew-Mode in {request:?}");
        let expected_version = format!("X-Brew-Version: {}\r\n", protocol::BREW_PROTOCOL_VERSION);
        assert!(request.contains(&expected_version), "no X-Brew-Version in {request:?}");
    }

    const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n/brew/";

    #[tokio::test]
    async fn discovery_without_auth_identifies_as_peer() {
        let (addr, server) = http_stub(vec![OK]).await;
        let peer = FederationPeerConfig { remote_host: addr, ..Default::default() };
        assert_eq!(discover(&peer, "/brew").await.unwrap(), "/brew/");
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("GET /brew HTTP/1.1\r\n"));
        assert_identifies_as_peer(&requests[0]);
    }

    #[tokio::test]
    async fn both_digest_requests_identify_as_peer() {
        // The far end keeps the mode of the *authorized* request, so the
        // retry must carry the headers as well as the first attempt.
        let challenge = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"r\", nonce=\"n\", qop=\"auth\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (addr, server) = http_stub(vec![challenge, OK]).await;
        let peer = FederationPeerConfig {
            remote_host: addr, username: "9000001".into(), password: "secret".into(), ..Default::default()
        };
        assert_eq!(discover(&peer, "/brew").await.unwrap(), "/brew/");
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in &requests { assert_identifies_as_peer(request); }
        assert!(!requests[0].contains("Authorization:"));
        assert!(requests[1].contains("Authorization: Digest username=\"9000001\""));
    }
}
