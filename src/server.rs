use crate::{fedroute, router, state::{AppState, Client, ClientMode}};
use crate::protocol::ConnVersion;
use anyhow::Context;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, FromRequestParts, Path, State,
    },
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub async fn run(state: Arc<AppState>) -> anyhow::Result<()> {
    let base = normalized_path(&state.config.websocket_path);
    let session_route = format!("{}/session/{{token}}", base);
    let mut app = Router::new().route(&base, get(brew_discovery));
    let slash = format!("{}/", base);
    if slash != base { app = app.route(&slash, get(brew_discovery)); }
    let app = app
        .route(&session_route, get(brew_session_endpoint))
        .route("/healthz", get(|| async { "ok\n" }))
        .with_state(state.clone());

    if state.config.tls.enabled {
        let tls = &state.config.tls;
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &tls.cert_path,
            &tls.key_path,
        )
        .await
        .with_context(|| {
            format!(
                "loading TLS cert {} and key {}",
                tls.cert_path.display(),
                tls.key_path.display()
            )
        })?;
        info!(listen=%state.config.listen, websocket_path=%base, auth=state.config.auth.enabled, tls=true, "Brew server listening (TLS)");
        axum_server::bind_rustls(state.config.listen, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(state.config.listen).await?;
        info!(listen=%state.config.listen, websocket_path=%base, auth=state.config.auth.enabled, tls=false, "Brew server listening");
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    }
    Ok(())
}

fn normalized_path(path: &str) -> String {
    let mut p = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    while p.len() > 1 && p.ends_with('/') { p.pop(); }
    p
}

/// HTTP header carrying the Brew protocol version, per the specification.
const X_BREW_VERSION: &str = "X-Brew-Version";
/// HTTP header carrying the Brew client mode (Terminal | Basestation).
const X_BREW_MODE: &str = "X-Brew-Mode";

fn brew_mode(headers: &HeaderMap) -> ClientMode {
    ClientMode::from_header(headers.get(X_BREW_MODE).and_then(|v| v.to_str().ok()))
}

/// Validates the client's advertised `X-Brew-Version` header against the version
/// this server implements and returns the connection's seed version. A missing
/// header is accepted for backward compatibility and seeds `V0` (the version is
/// then resolved lazily from message content, exactly as real clients do). A
/// present but unsupported version yields `426 Upgrade Required` (as listed in
/// the spec's supported response codes).
fn check_brew_version(headers: &HeaderMap) -> Result<ConnVersion, Response> {
    let Some(raw) = headers.get(X_BREW_VERSION) else {
        debug!("no X-Brew-Version header; seeding V0 and detecting lazily");
        return Ok(ConnVersion::V0);
    };
    let requested = raw.to_str().ok().and_then(|s| s.trim().parse::<u8>().ok());
    match requested {
        // Any version from 1 up to the version we implement is accepted; we seed
        // the highest layout we mutually support.
        Some(v) if v >= 1 && v <= crate::protocol::BREW_PROTOCOL_VERSION => {
            Ok(ConnVersion::from_header_value(Some(v)))
        }
        Some(0) => Ok(ConnVersion::V0),
        other => {
            warn!(requested=?other, supported=crate::protocol::BREW_PROTOCOL_VERSION, "unsupported X-Brew-Version");
            let mut resp = (
                StatusCode::UPGRADE_REQUIRED,
                [(header::CONTENT_TYPE, "text/plain")],
                format!("Unsupported Brew version; this server implements version {}\n", crate::protocol::BREW_PROTOCOL_VERSION),
            ).into_response();
            if let Ok(v) = HeaderValue::from_str(&crate::protocol::BREW_PROTOCOL_VERSION.to_string()) {
                resp.headers_mut().insert(X_BREW_VERSION, v);
            }
            Err(resp)
        }
    }
}

/// Mode and seed version a WebSocket upgrade runs with. Brew clients announce
/// both on the discovery GET (`discovered`); FlowStation sends neither on the
/// upgrade itself, while brew-server peers up to 1.12 sent them only on the
/// upgrade. An X-Brew-Mode on the upgrade wins; the version is the higher of
/// the two, so neither request can demote the other.
fn upgrade_mode_version(headers: &HeaderMap, discovered: Option<(ClientMode, ConnVersion)>) -> (ClientMode, ConnVersion) {
    let (mode, version) = discovered.unwrap_or_default();
    let mode = if headers.contains_key(X_BREW_MODE) { brew_mode(headers) } else { mode };
    // Only consulted when present, so a plain upgrade does not log the
    // "seeding V0" fallback for a version discovery already settled.
    let announced = if headers.contains_key(X_BREW_VERSION) {
        check_brew_version(headers).unwrap_or(ConnVersion::V0)
    } else {
        ConnVersion::V0
    };
    (mode, if announced.as_u8() > version.as_u8() { announced } else { version })
}

/// Loop-safe federation negotiation for one inbound connection: Ok(Some(neighbour_id))
/// when both sides speak it, Ok(None) for a legacy peer, Basestation or Terminal,
/// Err(()) when the peer claims our own server id (a link to ourselves).
fn negotiate_federation(mode: ClientMode, headers: &HeaderMap, loop_safe: bool, own_id: u64) -> Result<Option<u64>, ()> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if mode != ClientMode::Peer || !loop_safe || !fedroute::federation_offered(header(fedroute::X_BREW_FEDERATION)) {
        return Ok(None);
    }
    match header(fedroute::X_BREW_SERVER_ID).and_then(fedroute::parse_server_id) {
        Some(id) if id == own_id => Err(()),
        neighbour => Ok(neighbour),
    }
}

async fn brew_discovery(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
) -> Response {
    state.purge_ephemeral().await;
    let (mut parts, _body) = request.into_parts();
    let request_uri = parts.uri.path().to_string();

    let seed_version = match check_brew_version(&parts.headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let mode = brew_mode(&parts.headers);

    let is_upgrade = parts.headers.get(header::UPGRADE).and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket")).unwrap_or(false);

    // Direct WS mode remains available only when Digest is disabled. A
    // Basestation announces its mode and version on the discovery GET and
    // upgrades without them, so pick up what the same address announced
    // there (see `discovery_hints`); with no hint this is the upgrade's own
    // headers, as before.
    if is_upgrade && !state.config.auth.enabled {
        let hint = state.inner.write().await.discovery_hints.remove(&remote_addr.ip()).map(|(_, m, v)| (m, v));
        let (mode, seed_version) = upgrade_mode_version(&parts.headers, hint);
        return upgrade_from_parts(state, &mut parts, mode, seed_version, remote_addr, None).await;
    }

    if state.config.auth.enabled {
        let Some(username) = verify_digest(&state, &parts.headers, "GET", &request_uri).await else {
            return digest_challenge(&state).await;
        };
        let token = Uuid::new_v4().simple().to_string();
        state.inner.write().await.auth_sessions.insert(token.clone(), (Instant::now(), mode, seed_version, Some(username)));
        let path = format!("{}/session/{}", normalized_path(&state.config.websocket_path), token);
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain"),
                (header::HeaderName::from_static("x-brew-version"), version_header_value()),
            ],
            path,
        ).into_response();
    }

    if parts.headers.contains_key(X_BREW_MODE) || parts.headers.contains_key(X_BREW_VERSION) {
        state.inner.write().await.discovery_hints.insert(remote_addr.ip(), (Instant::now(), mode, seed_version));
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain"),
            (header::HeaderName::from_static("x-brew-version"), version_header_value()),
        ],
        normalized_path(&state.config.websocket_path),
    ).into_response()
}

fn version_header_value() -> &'static str {
    // BREW_PROTOCOL_VERSION is a small constant; map it to a static string so it
    // can be used directly in the header array without allocation.
    match crate::protocol::BREW_PROTOCOL_VERSION {
        1 => "1",
        _ => "1",
    }
}

async fn brew_session_endpoint(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
) -> Response {
    state.purge_ephemeral().await;
    if !state.config.auth.enabled { return StatusCode::NOT_FOUND.into_response(); }
    let valid = state.inner.read().await.auth_sessions.contains_key(&token);
    if !valid { return StatusCode::UNAUTHORIZED.into_response(); }

    let (mut parts, _body) = request.into_parts();
    let is_upgrade = parts.headers.get(header::UPGRADE).and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket")).unwrap_or(false);
    if !is_upgrade { return StatusCode::BAD_REQUEST.into_response(); }

    // Session URLs are single-use. The established WebSocket is the authenticated
    // session. Recover the mode, seed version and authenticated username
    // captured during the discovery GET; a Basestation's WebSocket handshake
    // carries neither the X-Brew-Mode/X-Brew-Version headers nor
    // Authorization. Older brew-server peers announce mode and version only
    // on the handshake, so those still count when present (see
    // `upgrade_mode_version`).
    let (stored_mode, stored_version, username) = state.inner.write().await.auth_sessions.remove(&token)
        .map(|(_, mode, ver, user)| (mode, ver, user))
        .unwrap_or_default();
    let (mode, seed_version) = upgrade_mode_version(&parts.headers, Some((stored_mode, stored_version)));
    upgrade_from_parts(state, &mut parts, mode, seed_version, remote_addr, username).await
}

async fn upgrade_from_parts(state: Arc<AppState>, parts: &mut axum::http::request::Parts, mode: ClientMode, seed_version: ConnVersion, remote_addr: SocketAddr, username: Option<String>) -> Response {
    // Decided on the upgrade's own headers, which every brew-server that
    // speaks it sends whether or not [auth] put a discovery GET in between.
    let own_id = state.inner.read().await.fed.self_id;
    let fed_neighbour = match negotiate_federation(mode, &parts.headers, state.config.federation.loop_safe, own_id) {
        Ok(neighbour) => neighbour,
        Err(()) => {
            warn!(%remote_addr, "federation peer presented this server's own id (a link to ourselves); refusing");
            return (StatusCode::CONFLICT, [(header::CONTENT_TYPE, "text/plain")], "Federation link to this server itself\n").into_response();
        }
    };
    match WebSocketUpgrade::from_request_parts(parts, &state).await {
        Ok(ws) => {
            let requested = parts.headers.get(header::SEC_WEBSOCKET_PROTOCOL).and_then(|v| v.to_str().ok()).unwrap_or_default();
            debug!(requested_subprotocol=requested, mode=mode.as_str(), seed_version=seed_version.as_u8(), loop_safe=fed_neighbour.is_some(), "WebSocket upgrade request");
            let protocol = state.config.websocket_subprotocol.clone();
            let mut response = ws.protocols([protocol])
                .on_upgrade(move |socket| client_session(state, socket, mode, seed_version, remote_addr, username, fed_neighbour))
                .into_response();
            if fed_neighbour.is_some() {
                // Accepting: the dialling side only switches to loop-safe mode
                // when it sees these in the 101.
                let headers = response.headers_mut();
                headers.insert(fedroute::X_BREW_FEDERATION, HeaderValue::from_static("1"));
                if let Ok(id) = HeaderValue::from_str(&fedroute::format_server_id(own_id)) {
                    headers.insert(fedroute::X_BREW_SERVER_ID, id);
                }
            }
            response
        }
        Err(rejection) => rejection.into_response(),
    }
}

async fn digest_challenge(state: &Arc<AppState>) -> Response {
    let nonce = Uuid::new_v4().simple().to_string();
    state.inner.write().await.digest_nonces.insert(nonce.clone(), Instant::now());
    let opaque = md5_hex(&format!("{}:brew", state.config.auth.realm));
    let challenge = format!("Digest realm=\"{}\", nonce=\"{}\", qop=\"auth\", opaque=\"{}\"",
        state.config.auth.realm, nonce, opaque);
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_str(&challenge).unwrap());
    response
}

fn md5_hex(input: &str) -> String { format!("{:x}", md5::compute(input.as_bytes())) }

fn parse_digest(header_value: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let value = header_value.trim().strip_prefix("Digest ").unwrap_or(header_value.trim());
    for part in value.split(',') {
        if let Some((k, v)) = part.trim().split_once('=') {
            out.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

/// Maximum number of digits allowed in a Brew (Basestation) username. TETRA
/// subscriber identities used as Brew usernames are constrained to at most 7
/// decimal digits.
const MAX_BREW_USERNAME_DIGITS: usize = 7;

/// A Brew username must be non-empty, all decimal digits, and at most
/// `MAX_BREW_USERNAME_DIGITS` long.
fn is_valid_brew_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_BREW_USERNAME_DIGITS
        && username.bytes().all(|b| b.is_ascii_digit())
}

/// Verifies a Digest `Authorization` header and, on success, returns the
/// authenticated Brew username -- the caller threads it through so the
/// connection's `Client.username` can be matched against `[bts_locations]`.
async fn verify_digest(state: &Arc<AppState>, headers: &HeaderMap, method: &str, expected_uri: &str) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    if !value.starts_with("Digest ") { return None; }
    let p = parse_digest(value);
    let username = p.get("username")?;
    if !is_valid_brew_username(username) {
        warn!(username = %username, "rejecting Brew auth: username must be 1-7 digits");
        return None;
    }
    let password = state.config.auth.users.get(username)?;
    let nonce = p.get("nonce")?;
    if !state.inner.read().await.digest_nonces.contains_key(nonce) { return None; }
    let realm = p.get("realm").map(String::as_str).unwrap_or("");
    if realm != state.config.auth.realm { return None; }
    let uri = p.get("uri").map(String::as_str).unwrap_or("");
    if uri != expected_uri { return None; }
    let received = p.get("response")?;

    let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
    let ha2 = md5_hex(&format!("{}:{}", method, uri));
    let expected = if p.get("qop").map(|s| s.contains("auth")).unwrap_or(false) {
        let nc = p.get("nc").map(String::as_str).unwrap_or("");
        let cnonce = p.get("cnonce").map(String::as_str).unwrap_or("");
        md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2))
    } else {
        md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2))
    };
    let ok = expected.eq_ignore_ascii_case(received);
    if !ok { return None; }
    state.inner.write().await.digest_nonces.remove(nonce);
    Some(username.clone())
}

async fn client_session(state: Arc<AppState>, socket: WebSocket, mode: ClientMode, seed_version: ConnVersion, remote_addr: SocketAddr, username: Option<String>, fed_neighbour: Option<u64>) {
    let id = Uuid::new_v4();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let connected_at_ms = crate::telemetry::now_ms();
    // An inbound federation peer link gets this server's full table too:
    // `federation::run`'s outbound dial side syncs its own state to us once
    // connected, but that is only half the story -- an inbound-only link (or
    // one that reconnects from the far end) would otherwise never learn about
    // registrations that predate it.
    let client = Client { tx, mode, version: seed_version, remote_addr: Some(remote_addr), connected_at_ms, username: username.clone() };
    crate::federation::attach_client(&state, id, client, fed_neighbour).await;
    info!(%id, mode=mode.as_str(), version=seed_version.as_u8(), %remote_addr, username=username.as_deref().unwrap_or(""),
        loop_safe_neighbour=fed_neighbour.map(fedroute::format_server_id).unwrap_or_default(), "Basestation connected");

    // A federation link is pinged and closed once silent (see
    // `federation::Keepalive`), the same as the links we dial out. Basestations
    // and Terminals are left alone: real Basestations run their own heartbeat
    // and reconnect, and a Terminal may be a phone app whose socket the OS
    // suspends in the background.
    let keepalive = if mode == ClientMode::Peer {
        crate::federation::Keepalive::from_config(&state.config.federation)
    } else {
        None
    };
    let mut ping = keepalive.map(crate::federation::Keepalive::ping_timer);
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                packet = rx.recv() => {
                    let Some(packet) = packet else { break };
                    if ws_tx.send(Message::Binary(packet.into())).await.is_err() { break; }
                }
                _ = crate::federation::ping_due(&mut ping) => {
                    if ws_tx.send(Message::Ping(Default::default())).await.is_err() { break; }
                }
            }
        }
    });

    loop {
        let item = match crate::federation::next_frame(&mut ws_rx, keepalive).await {
            Ok(Some(item)) => item,
            Ok(None) => break,
            Err(_) => { warn!(%id, %remote_addr, "peer link silent past keepalive timeout; closing"); break; }
        };
        match item {
            Ok(Message::Binary(data)) => router::handle_packet(state.clone(), id, data.to_vec()).await,
            Ok(Message::Ping(_)) => debug!(%id, "ping received"),
            Ok(Message::Pong(_)) => debug!(%id, "pong received"),
            Ok(Message::Close(_)) => break,
            Ok(Message::Text(_)) => warn!(%id, "text WebSocket message ignored"),
            Err(e) => { warn!(%id, error=%e, "WebSocket receive error"); break; }
        }
    }

    writer.abort();
    state.cleanup_client(id).await;
    info!(%id, "Basestation disconnected");
}

#[cfg(test)]
mod tests {
    use super::{is_valid_brew_username, negotiate_federation, upgrade_mode_version, ClientMode, ConnVersion, HeaderMap};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs { h.insert(*k, v.parse().unwrap()); }
        h
    }

    #[test]
    fn plain_upgrade_keeps_what_discovery_announced() {
        // FlowStation: mode/version on the discovery GET only.
        let discovered = Some((ClientMode::Terminal, ConnVersion::V1));
        assert_eq!(upgrade_mode_version(&headers(&[]), discovered), (ClientMode::Terminal, ConnVersion::V1));
        assert_eq!(upgrade_mode_version(&headers(&[]), None), (ClientMode::Basestation, ConnVersion::V0));
    }

    #[test]
    fn old_peer_announcing_on_upgrade_only_is_recognised() {
        // brew-server <= 1.12 dialling a server with [auth]: the discovery GET
        // carried nothing, so the session token holds the defaults.
        let upgrade = headers(&[("X-Brew-Mode", "Peer"), ("X-Brew-Version", "1")]);
        let discovered = Some((ClientMode::Basestation, ConnVersion::V0));
        assert_eq!(upgrade_mode_version(&upgrade, discovered), (ClientMode::Peer, ConnVersion::V1));
    }

    #[test]
    fn upgrade_never_demotes_the_discovered_version() {
        let upgrade = headers(&[("X-Brew-Version", "0")]);
        assert_eq!(upgrade_mode_version(&upgrade, Some((ClientMode::Peer, ConnVersion::V1))), (ClientMode::Peer, ConnVersion::V1));
        let bogus = headers(&[("X-Brew-Version", "99")]);
        assert_eq!(upgrade_mode_version(&bogus, Some((ClientMode::Peer, ConnVersion::V1))), (ClientMode::Peer, ConnVersion::V1));
    }

    #[test]
    fn negotiate_federation_only_between_loop_safe_peers() {
        let offer = headers(&[("X-Brew-Federation", "1"), ("X-Brew-Server-Id", "00a1b2c3d4e5f607")]);
        assert_eq!(negotiate_federation(ClientMode::Peer, &offer, true, 7), Ok(Some(0x00a1_b2c3_d4e5_f607)));
        // Not loop-safe here, not a peer, or no offer: a plain link.
        assert_eq!(negotiate_federation(ClientMode::Peer, &offer, false, 7), Ok(None));
        assert_eq!(negotiate_federation(ClientMode::Basestation, &offer, true, 7), Ok(None));
        assert_eq!(negotiate_federation(ClientMode::Terminal, &offer, true, 7), Ok(None));
        assert_eq!(negotiate_federation(ClientMode::Peer, &headers(&[]), true, 7), Ok(None));
    }

    #[test]
    fn negotiate_federation_needs_a_valid_offer() {
        let id = ("X-Brew-Server-Id", "00a1b2c3d4e5f607");
        for bad in [
            headers(&[("X-Brew-Federation", "0"), id]),
            headers(&[("X-Brew-Federation", "yes"), id]),
            headers(&[id]),
            headers(&[("X-Brew-Federation", "1")]),
            headers(&[("X-Brew-Federation", "1"), ("X-Brew-Server-Id", "a1b2c3d4e5f607")]),
            headers(&[("X-Brew-Federation", "1"), ("X-Brew-Server-Id", "00a1b2c3d4e5f60z")]),
        ] {
            assert_eq!(negotiate_federation(ClientMode::Peer, &bad, true, 7), Ok(None), "{bad:?}");
        }
        // A later version is still version 1 to us.
        let newer = headers(&[("X-Brew-Federation", "2"), id]);
        assert_eq!(negotiate_federation(ClientMode::Peer, &newer, true, 7), Ok(Some(0x00a1_b2c3_d4e5_f607)));
    }

    #[test]
    fn negotiate_federation_refuses_our_own_id() {
        let offer = headers(&[("X-Brew-Federation", "1"), ("X-Brew-Server-Id", "00a1b2c3d4e5f607")]);
        assert_eq!(negotiate_federation(ClientMode::Peer, &offer, true, 0x00a1_b2c3_d4e5_f607), Err(()));
    }

    #[tokio::test]
    async fn negotiate_federation_on_a_real_upgrade() {
        use super::{brew_discovery, get, AppState, Arc, SocketAddr};
        use std::time::Duration;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let mut cfg = crate::config::Config::default();
        cfg.storage.enabled = false;
        cfg.sms_center.enabled = false;
        cfg.federation.loop_safe = true;
        let state = Arc::new(AppState::new(cfg, "test.toml".into()).0);
        let own_id = state.inner.read().await.fed.self_id;
        let app = axum::Router::new().route("/brew", get(brew_discovery)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
        });
        let upgrade = |pairs: &[(&'static str, String)]| {
            let mut request = format!("ws://{addr}/brew").into_client_request().unwrap();
            request.headers_mut().insert("X-Brew-Mode", "Peer".parse().unwrap());
            for (k, v) in pairs { request.headers_mut().insert(*k, v.parse().unwrap()); }
            tokio_tungstenite::connect_async(request)
        };

        let (_link, resp) = upgrade(&[("X-Brew-Federation", "1".into()), ("X-Brew-Server-Id", "00000000000000aa".into())]).await.unwrap();
        assert_eq!(resp.headers()["X-Brew-Federation"], "1");
        assert_eq!(resp.headers()["X-Brew-Server-Id"], crate::fedroute::format_server_id(own_id).as_str());
        let (_legacy, resp) = upgrade(&[]).await.unwrap();
        assert!(!resp.headers().contains_key("X-Brew-Federation"), "an older peer is not answered with it");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while state.inner.read().await.clients.len() < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let neighbours: Vec<u64> = state.inner.read().await.fed.links.values().copied().collect();
        assert_eq!(neighbours, vec![0xaa], "only the negotiated link is loop-safe");

        let ours = crate::fedroute::format_server_id(own_id);
        let err = upgrade(&[("X-Brew-Federation", "1".into()), ("X-Brew-Server-Id", ours)]).await.unwrap_err();
        assert!(err.to_string().contains("409"), "{err}");
    }

    #[test]
    fn accepts_1_to_7_digits() {
        assert!(is_valid_brew_username("1"));
        assert!(is_valid_brew_username("1234567"));
        assert!(is_valid_brew_username("90"));
    }

    #[test]
    fn rejects_more_than_7_digits() {
        assert!(!is_valid_brew_username("12345678"));   // 8 digits
        assert!(!is_valid_brew_username("100000001"));  // old 9-digit example
    }

    #[test]
    fn rejects_empty_and_non_digits() {
        assert!(!is_valid_brew_username(""));
        assert!(!is_valid_brew_username("12a4567"));
        assert!(!is_valid_brew_username("bs1"));
        assert!(!is_valid_brew_username(" 123456"));
        assert!(!is_valid_brew_username("123-456"));
    }

    #[tokio::test]
    async fn silent_inbound_peer_is_dropped_but_basestation_is_not() {
        use super::{brew_discovery, get, AppState, Arc, SocketAddr};
        use std::time::Duration;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let mut cfg = crate::config::Config::default();
        cfg.storage.enabled = false;
        cfg.sms_center.enabled = false;
        cfg.federation.keepalive_interval_seconds = 1;
        cfg.federation.keepalive_timeout_seconds = 2;
        let state = Arc::new(AppState::new(cfg, "test.toml".into()).0);
        let app = axum::Router::new().route("/brew", get(brew_discovery)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
        });

        // Neither client is ever read from, so neither answers a ping.
        let mut peer_request = format!("ws://{addr}/brew").into_client_request().unwrap();
        peer_request.headers_mut().insert("X-Brew-Mode", "Peer".parse().unwrap());
        let (_peer, _) = tokio_tungstenite::connect_async(peer_request).await.unwrap();
        let (_basestation, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/brew")).await.unwrap();

        let modes = || async {
            state.inner.read().await.clients.values().map(|c| c.mode).collect::<Vec<_>>()
        };
        let wait_for = |n: usize, within: Duration| async move {
            let deadline = tokio::time::Instant::now() + within;
            while modes().await.len() != n && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        wait_for(2, Duration::from_secs(2)).await;
        assert_eq!(modes().await.len(), 2, "both connections registered");
        wait_for(1, Duration::from_secs(6)).await;
        // Margin: had the Basestation been pinged too, it would go at the same time.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(modes().await, vec![ClientMode::Basestation]);
    }

    #[tokio::test]
    async fn without_auth_the_upgrade_takes_what_discovery_announced() {
        use super::{brew_discovery, get, AppState, SocketAddr};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let state = AppState::for_test();
        let app = axum::Router::new().route("/brew", get(brew_discovery)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
        });
        let connected = || async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                let clients: Vec<_> = state.inner.read().await.clients.values().map(|c| (c.mode, c.version)).collect();
                if !clients.is_empty() || tokio::time::Instant::now() >= deadline { return clients; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };

        // FlowStation: mode and version on the discovery GET, a bare upgrade.
        let mut http = tokio::net::TcpStream::connect(addr).await.unwrap();
        http.write_all(b"GET /brew HTTP/1.1\r\nHost: x\r\nX-Brew-Mode: Terminal\r\nX-Brew-Version: 1\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        http.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/brew")).await.unwrap();
        assert_eq!(connected().await, vec![(ClientMode::Terminal, ConnVersion::V1)]);
        drop(ws);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.inner.read().await.clients.is_empty() { tokio::time::sleep(Duration::from_millis(20)).await; }
        }).await.expect("closed connection cleaned up");

        // The hint is used once: a later bare upgrade gets the defaults again.
        let (_ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/brew")).await.unwrap();
        assert_eq!(connected().await, vec![(ClientMode::Basestation, ConnVersion::V0)]);
    }
}
