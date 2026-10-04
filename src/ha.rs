//! Active/standby high availability (`[ha]`).
//!
//! Two nodes on one Layer 2 segment exchange HMAC-signed UDP heartbeats over
//! their real IPs. Exactly one of them is Active and holds the virtual IP;
//! Basestations, terminals and federation peers connect to the VIP, so a
//! failover is just a reconnect for them.
//!
//! The election (`Election`) is a pure state machine driven by `tick`; the
//! runtime (`run`) feeds it heartbeats, the gateway check and dashboard
//! commands, and moves the VIP (`Vip`) whenever the role changes.
//!
//! Role changes are driven by the Active node wherever possible: it hands
//! over to the peer (`handover_to`) for preemption and manual switches, and
//! steps down first, so the two never hold the VIP at the same time in
//! normal operation. If both do end up Active (a healed partition) the
//! lower-ranked one steps down at once.

use crate::config::HaConfig;
use crate::state::AppState;
use anyhow::{Context, Result};
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

/// How long a handover (or a takeover request) waits for the peer to act
/// before it is abandoned and the normal rules apply again.
const HANDOVER_TIMEOUT_MS: u64 = 5000;
/// Heartbeats whose timestamp is further than this from our clock are
/// dropped (replay guard; keep both nodes on NTP).
const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const TAG_LEN: usize = 32;
const TRANSITION_LOG_LEN: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Just started: listening for the peer before claiming anything.
    Init,
    Standby,
    Active,
    /// The gateway check failed: this node must not hold the VIP.
    Fault,
}

/// What a node announces in every heartbeat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub node: String,
    /// Random per process start, so `seq` can restart from zero.
    pub boot_id: u64,
    pub seq: u64,
    pub ts_ms: u64,
    pub role: Role,
    pub weight: u32,
    pub persist: bool,
    /// Active after a manual switch: not preempted until it leaves Active.
    pub hold: bool,
    /// "Take over from me": sent by the Active node while it hands over.
    pub handover_to: Option<String>,
    /// Whether that handover is a manual switch (the new Active gets `hold`).
    pub handover_manual: bool,
    /// "Please hand over to me": the dashboard's Make Active on a Standby.
    pub takeover_request: bool,
    /// Hash of the config file, so the dashboard can flag a mismatch.
    pub config_hash: u64,
}

/// The parts of the peer's heartbeat the election looks at.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerView {
    pub node: String,
    pub role: Role,
    pub weight: u32,
    pub persist: bool,
    pub hold: bool,
    pub handover_to: Option<String>,
    pub handover_manual: bool,
    pub takeover_request: bool,
}

impl From<&Heartbeat> for PeerView {
    fn from(h: &Heartbeat) -> Self {
        Self {
            node: h.node.clone(),
            role: h.role,
            weight: h.weight,
            persist: h.persist,
            hold: h.hold,
            handover_to: h.handover_to.clone(),
            handover_manual: h.handover_manual,
            takeover_request: h.takeover_request,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Handover {
    to: String,
    manual: bool,
    until_ms: u64,
}

/// The election state machine. Pure: time comes in as `now_ms`, the peer as
/// the last valid heartbeat (or `None` when it is dead).
#[derive(Debug, Clone)]
pub struct Election {
    pub node: String,
    pub weight: u32,
    pub persist: bool,
    pub role: Role,
    pub hold: bool,
    handover: Option<Handover>,
    takeover_until_ms: Option<u64>,
    init_until_ms: u64,
}

impl Election {
    pub fn new(node: &str, weight: u32, persist: bool, now_ms: u64, listen_ms: u64) -> Self {
        Self {
            node: node.to_owned(),
            weight,
            persist,
            role: Role::Init,
            hold: false,
            handover: None,
            takeover_until_ms: None,
            init_until_ms: now_ms + listen_ms,
        }
    }

    /// Preferred Active when both are healthy: higher weight, then name.
    fn preferred(a: (u32, &str), b: (u32, &str)) -> bool {
        a > b
    }

    /// Split-brain ranking: a node that is entitled to stay (persist or
    /// manual hold) outranks one that is not; then the normal preference.
    fn outranks(a: (bool, u32, &str), b: (bool, u32, &str)) -> bool {
        a > b
    }

    pub fn handover_target(&self) -> Option<(&str, bool)> {
        self.handover.as_ref().map(|h| (h.to.as_str(), h.manual))
    }

    pub fn takeover_requested(&self, now_ms: u64) -> bool {
        self.takeover_until_ms.is_some_and(|t| now_ms < t)
    }

    /// Dashboard "Make Standby" on the Active node: hand over to the peer.
    pub fn request_standby(&mut self, peer: Option<&PeerView>, now_ms: u64) -> Result<(), &'static str> {
        self.request_handover(peer, now_ms, true)
    }

    /// Hands over to a healthy Standby peer. `manual` gives the peer a hold;
    /// without it (e.g. a restart to apply config) the usual weight and
    /// persist rules decide who ends up Active afterwards.
    pub fn request_handover(&mut self, peer: Option<&PeerView>, now_ms: u64, manual: bool) -> Result<(), &'static str> {
        if self.role != Role::Active {
            return Err("this node is not Active");
        }
        let Some(peer) = peer.filter(|p| matches!(p.role, Role::Standby | Role::Init)) else {
            return Err("no healthy Standby peer to hand over to");
        };
        self.start_handover(&peer.node.clone(), manual, now_ms);
        Ok(())
    }

    /// Dashboard "Make Active" on the Standby node: ask the peer to hand over
    /// (or, if the peer is not Active, take over directly on the next tick).
    pub fn request_active(&mut self, peer: Option<&PeerView>, now_ms: u64) -> Result<(), &'static str> {
        match self.role {
            Role::Active => return Err("this node is already Active"),
            Role::Fault => return Err("this node is in Fault (gateway unreachable)"),
            Role::Init => return Err("this node is still starting up"),
            Role::Standby => {}
        }
        if peer.is_none() {
            return Err("peer is not reachable");
        }
        self.takeover_until_ms = Some(now_ms + HANDOVER_TIMEOUT_MS);
        Ok(())
    }

    fn start_handover(&mut self, to: &str, manual: bool, now_ms: u64) {
        self.handover = Some(Handover { to: to.to_owned(), manual, until_ms: now_ms + HANDOVER_TIMEOUT_MS });
        self.set_role(Role::Standby);
    }

    fn set_role(&mut self, role: Role) {
        if role != Role::Active {
            self.hold = false;
        }
        if role != Role::Standby {
            self.takeover_until_ms = None;
        }
        self.role = role;
    }

    /// Advances the state machine and returns the new role.
    pub fn tick(&mut self, now_ms: u64, peer: Option<&PeerView>, gateway_ok: bool) -> Role {
        if self.takeover_until_ms.is_some_and(|t| now_ms >= t) {
            self.takeover_until_ms = None;
        }
        if !gateway_ok {
            self.handover = None;
            self.set_role(Role::Fault);
            return self.role;
        }
        if self.role == Role::Fault {
            // Gateway is back: start over as if freshly booted, without the
            // listen delay (we have been hearing the peer all along).
            self.set_role(Role::Init);
            self.init_until_ms = now_ms;
        }
        if self.role == Role::Init && now_ms < self.init_until_ms && peer.is_none() {
            return self.role;
        }

        let Some(p) = peer else {
            self.handover = None;
            self.set_role(Role::Active);
            return self.role;
        };

        // A handover we started: stay Standby until the peer is Active or it
        // times out.
        if let Some(h) = &self.handover {
            if p.role == Role::Active || now_ms >= h.until_ms {
                self.handover = None;
            } else {
                self.set_role(Role::Standby);
                return self.role;
            }
        }

        // The peer hands over to us.
        if p.handover_to.as_deref() == Some(self.node.as_str()) {
            let manual = p.handover_manual;
            self.set_role(Role::Active);
            self.hold = manual;
            return self.role;
        }

        if p.role == Role::Fault {
            if self.role != Role::Active {
                self.set_role(Role::Active);
            }
            return self.role;
        }

        let me = (self.weight, self.node.as_str());
        let them = (p.weight, p.node.as_str());
        match self.role {
            Role::Active => {
                if p.role == Role::Active {
                    let mine = (self.persist || self.hold, self.weight, self.node.as_str());
                    let theirs = (p.persist || p.hold, p.weight, p.node.as_str());
                    if Self::outranks(theirs, mine) {
                        warn!(peer = %p.node, "both nodes Active; stepping down");
                        self.set_role(Role::Standby);
                    }
                } else if p.takeover_request {
                    let to = p.node.clone();
                    self.start_handover(&to, true, now_ms);
                } else if !self.persist && !self.hold && Self::preferred(them, me) {
                    let to = p.node.clone();
                    self.start_handover(&to, false, now_ms);
                }
            }
            Role::Standby | Role::Init => {
                if p.role != Role::Active {
                    let takeover = self.takeover_requested(now_ms);
                    if takeover || Self::preferred(me, them) {
                        self.set_role(Role::Active);
                        self.hold = takeover;
                    } else {
                        self.set_role(Role::Standby);
                    }
                } else {
                    self.set_role(Role::Standby);
                }
            }
            Role::Fault => unreachable!("handled above"),
        }
        self.role
    }
}

// ---------------------------------------------------------------------------
// Wire format: JSON heartbeat followed by a 32-byte HMAC-SHA256 tag.

pub fn encode(key: &hmac::Key, hb: &Heartbeat) -> Vec<u8> {
    let mut buf = serde_json::to_vec(hb).expect("heartbeat serializes");
    let tag = hmac::sign(key, &buf);
    buf.extend_from_slice(tag.as_ref());
    buf
}

pub fn decode(key: &hmac::Key, buf: &[u8]) -> Option<Heartbeat> {
    if buf.len() <= TAG_LEN {
        return None;
    }
    let (body, tag) = buf.split_at(buf.len() - TAG_LEN);
    hmac::verify(key, body, tag).ok()?;
    serde_json::from_slice(body).ok()
}

/// Replay/staleness guard on an authenticated heartbeat.
#[derive(Default)]
struct ReplayGuard {
    last: Option<(u64, u64)>,
}

impl ReplayGuard {
    fn accept(&mut self, hb: &Heartbeat, now_ms: u64) -> bool {
        if now_ms.abs_diff(hb.ts_ms) > MAX_CLOCK_SKEW_MS {
            return false;
        }
        match self.last {
            Some((boot, seq)) if boot == hb.boot_id && hb.seq <= seq => false,
            _ => {
                self.last = Some((hb.boot_id, hb.seq));
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime toggles persisted across restarts (set from the dashboard).

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HaState {
    /// Dashboard override of `[ha] persist`; `None` = use the config value.
    pub persist_override: Option<bool>,
    /// Recent role changes, newest first, kept across the restart a node
    /// does when it stops being Active.
    pub transitions: VecDeque<Transition>,
}

impl HaState {
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                warn!(path = %path.display(), error = %e, "ignoring unreadable HA state file");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VIP driver: `ip addr` + gratuitous ARP (iputils `arping`).

pub struct Vip {
    cidr: String,
    addr: String,
    iface: String,
}

impl Vip {
    pub fn new(cfg: &HaConfig) -> Result<Self> {
        let (addr, prefix) = cfg.vip_parts()?;
        Ok(Self { cidr: format!("{addr}/{prefix}"), addr: addr.to_string(), iface: cfg.vip_interface.clone() })
    }

    async fn ip(&self, verb: &str) -> Result<std::process::Output> {
        tokio::process::Command::new("ip")
            .args(["-4", "addr", verb, &self.cidr, "dev", &self.iface])
            .output()
            .await
            .context("running `ip`")
    }

    /// Adds the VIP (already present is fine) and announces it.
    pub async fn up(&self) -> Result<()> {
        let out = self.ip("add").await?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !stderr.contains("File exists") {
            anyhow::bail!("ip addr add {} dev {}: {}", self.cidr, self.iface, stderr.trim());
        }
        // Unsolicited ARP so switches and Basestations repoint the VIP at us.
        match tokio::process::Command::new("arping")
            .args(["-U", "-c", "3", "-I", &self.iface, &self.addr])
            .output()
            .await
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => warn!(stderr = %String::from_utf8_lossy(&o.stderr).trim(), "gratuitous ARP failed"),
            Err(e) => warn!(error = %e, "cannot run arping; peers may keep a stale ARP entry for the VIP"),
        }
        Ok(())
    }

    /// Removes the VIP (already absent is fine).
    pub async fn down(&self) -> Result<()> {
        let out = self.ip("del").await?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        let absent = stderr.contains("Cannot assign requested address") || stderr.contains("Address not found");
        if !out.status.success() && !absent {
            anyhow::bail!("ip addr del {} dev {}: {}", self.cidr, self.iface, stderr.trim());
        }
        Ok(())
    }
}

async fn ping(ip: &str) -> bool {
    tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", ip])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------
// Runtime.

/// Dashboard-facing snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct HaStatus {
    pub enabled: bool,
    pub node: String,
    pub role: Role,
    pub weight: u32,
    pub persist: bool,
    /// "config" or "override".
    pub persist_source: &'static str,
    pub hold: bool,
    pub vip: String,
    pub vip_held: bool,
    pub gateway_ok: bool,
    pub handover_to: Option<String>,
    pub peer: Option<PeerStatus>,
    pub config_hash: u64,
    pub transitions: VecDeque<Transition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerStatus {
    pub node: String,
    pub ip: IpAddr,
    pub alive: bool,
    pub role: Role,
    pub weight: u32,
    pub persist: bool,
    pub hold: bool,
    pub last_seen_ms_ago: u64,
    pub config_hash: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transition {
    pub ts_ms: u64,
    pub from: Role,
    pub to: Role,
    pub reason: String,
}

pub enum HaCommand {
    MakeActive(oneshot::Sender<Result<(), String>>),
    MakeStandby(oneshot::Sender<Result<(), String>>),
    /// `None` clears the override (back to the config value).
    SetPersist(Option<bool>, oneshot::Sender<Result<(), String>>),
    /// Restart to apply the saved config file. On the Active node with a
    /// healthy Standby peer, hands over first; with `force`, restarts the
    /// Active node even when no peer can take over (service drops).
    Apply { force: bool, reply: oneshot::Sender<Result<String, String>> },
}

/// Shared between the HA task and the rest of the server.
pub struct HaHandle {
    pub status: watch::Sender<HaStatus>,
    pub commands: mpsc::UnboundedSender<HaCommand>,
    commands_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<HaCommand>>>,
}

impl HaHandle {
    pub fn new(cfg: &HaConfig, config_hash: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let status = HaStatus {
            enabled: cfg.enabled,
            node: cfg.node_name.clone(),
            role: if cfg.enabled { Role::Init } else { Role::Active },
            weight: cfg.weight,
            persist: cfg.persist,
            persist_source: "config",
            hold: false,
            vip: cfg.vip.clone(),
            vip_held: false,
            gateway_ok: true,
            handover_to: None,
            peer: None,
            config_hash,
            transitions: VecDeque::new(),
        };
        Self { status: watch::channel(status).0, commands: tx, commands_rx: std::sync::Mutex::new(Some(rx)) }
    }

    /// Sends a dashboard command to the HA task and waits for its answer.
    pub async fn command<T>(&self, make: impl FnOnce(oneshot::Sender<Result<T, String>>) -> HaCommand) -> Result<T, String> {
        let (tx, rx) = oneshot::channel();
        if !self.status.borrow().enabled || self.commands.send(make(tx)).is_err() {
            return Err("HA is not enabled".into());
        }
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(r)) => r,
            _ => Err("HA task did not answer".into()),
        }
    }

    /// Resolves once this node is Active (immediately with HA disabled).
    pub async fn wait_active(&self) {
        let mut rx = self.status.subscribe();
        let _ = rx.wait_for(|s| s.role == Role::Active).await;
    }
}

/// After a handover on a shared host, the old Active node still holds the
/// VIP ports until it restarts (within about a heartbeat of seeing us take
/// over). Waits, up to a limit, for every enabled service's VIP port to be
/// bindable, so the listeners don't fail with "address in use".
pub async fn wait_ports_free(state: &AppState) {
    let c = &state.config;
    let mut tcp = vec![state.service_bind(c.listen)];
    if c.telemetry.enabled { tcp.push(state.service_bind(c.telemetry.listen)); }
    if c.control.enabled { tcp.push(state.service_bind(c.control.listen)); }
    let udp = c.sip.enabled.then(|| state.service_bind(c.sip.listen));
    let free = || {
        tcp.iter().all(|a| std::net::TcpListener::bind(a).is_ok())
            && udp.is_none_or(|a| std::net::UdpSocket::bind(a).is_ok())
    };
    for _ in 0..100 {
        if free() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    warn!("service ports still in use after 10s; starting anyway");
}

/// FNV-1a: stable across builds, unlike `DefaultHasher`, so both nodes agree.
pub fn config_hash(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
}

fn now_ms() -> u64 {
    crate::telemetry::now_ms()
}

struct LastPeer {
    hb: Heartbeat,
    at_ms: u64,
}

/// Runs the HA node until the process exits. Returns immediately with HA
/// disabled.
pub async fn run(state: Arc<AppState>) -> Result<()> {
    let cfg = state.config.ha.clone();
    if !cfg.enabled {
        return Ok(());
    }
    let mut commands = state.ha.commands_rx.lock().unwrap().take().context("ha::run started twice")?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, cfg.shared_secret.as_bytes());
    let vip = Vip::new(&cfg)?;
    let config_hash = state.ha.status.borrow().config_hash;

    // A VIP left behind by a crash: drop it before the election, so we never
    // answer for it while not Active. Not when both nodes share this host:
    // there is only one VIP on the interface, and it may be the peer's.
    let shared_host = std::net::UdpSocket::bind(SocketAddr::new(cfg.peer_ip, 0)).is_ok();
    if shared_host {
        info!("peer runs on this host; leaving any existing VIP alone at startup");
    } else if let Err(e) = vip.down().await {
        error!(error = %e, "cannot clear the VIP at startup (missing CAP_NET_ADMIN?)");
    }

    let bind = SocketAddr::new(cfg.real_ip, cfg.heartbeat_port);
    let peer_addr = SocketAddr::new(cfg.peer_ip, cfg.heartbeat_port);
    let sock = UdpSocket::bind(bind).await.with_context(|| format!("binding HA heartbeat socket {bind}"))?;
    info!(node = %cfg.node_name, %bind, peer = %peer_addr, vip = %cfg.vip, weight = cfg.weight, "HA starting");

    let mut ha_state = HaState::load(&cfg.state_path);
    let persist = ha_state.persist_override.unwrap_or(cfg.persist);
    state.ha.status.send_modify(|s| s.transitions = ha_state.transitions.clone());
    let mut was_active = false;
    // Set by an Apply that hands over first: restart once the handover ends.
    let mut apply_pending = false;
    let mut election = Election::new(&cfg.node_name, cfg.weight, persist, now_ms(), cfg.dead_after_ms);
    let mut guard = ReplayGuard::default();
    let mut last_peer: Option<LastPeer> = None;
    let boot_id: u64 = rand_u64();
    let mut seq = 0u64;
    let mut vip_held = false;
    // A failed VIP add counts as Fault for a while, so the peer takes over
    // instead of us claiming Active without the address.
    let mut vip_fault_until_ms = 0u64;

    // Gateway check runs on its own so a slow ping never delays heartbeats.
    let mut gw_ok = true;
    if !cfg.check_gateway.is_empty() {
        // Settle the gateway state before the election starts, so a node
        // without an uplink never briefly claims the VIP after a restart.
        gw_ok = false;
        for _ in 0..3 {
            if ping(&cfg.check_gateway).await { gw_ok = true; break; }
        }
        if !gw_ok { warn!(gateway = %cfg.check_gateway, "gateway unreachable at startup"); }
    }
    let (gw_tx, gw_rx) = watch::channel(gw_ok);
    if !cfg.check_gateway.is_empty() {
        let gw = cfg.check_gateway.clone();
        tokio::spawn(async move {
            let mut misses = if gw_ok { 0u32 } else { 3 };
            loop {
                if ping(&gw).await { misses = 0 } else { misses += 1 }
                // Three misses in a row before declaring Fault.
                let _ = gw_tx.send(misses < 3);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(cfg.heartbeat_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buf = vec![0u8; 2048];
    let mut sigterm = signal_stream()?;

    loop {
        let mut reason = String::new();
        tokio::select! {
            _ = ticker.tick() => {}
            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, from)) if from.ip() == cfg.peer_ip => {
                        match decode(&key, &buf[..n]) {
                            Some(hb) if hb.node == cfg.node_name => {
                                warn!("peer heartbeat uses our own node_name; ignoring");
                                continue;
                            }
                            Some(hb) if guard.accept(&hb, now_ms()) => {
                                last_peer = Some(LastPeer { hb, at_ms: now_ms() });
                            }
                            Some(_) => continue,
                            None => { warn!(%from, "dropping HA heartbeat with bad signature"); continue; }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => { warn!(error = %e, "HA heartbeat receive failed"); continue; }
                }
            }
            Some(cmd) = commands.recv() => {
                let now = now_ms();
                let peer = alive_peer(&last_peer, now, cfg.dead_after_ms);
                match cmd {
                    HaCommand::MakeActive(reply) => {
                        let r = election.request_active(peer.as_ref(), now).map_err(str::to_owned);
                        if r.is_ok() { reason = "manual: make active".into(); }
                        let _ = reply.send(r);
                    }
                    HaCommand::MakeStandby(reply) => {
                        let r = election.request_standby(peer.as_ref(), now).map_err(str::to_owned);
                        if r.is_ok() { reason = "manual: make standby".into(); }
                        let _ = reply.send(r);
                    }
                    HaCommand::Apply { force, reply } => {
                        if election.role == Role::Active {
                            match election.request_handover(peer.as_ref(), now, false) {
                                Ok(()) => {
                                    apply_pending = true;
                                    reason = "manual: apply config (handover)".into();
                                    let _ = reply.send(Ok("handing over to the peer, then restarting".into()));
                                }
                                Err(e) if !force => { let _ = reply.send(Err(format!("{e}; confirm to restart anyway (service drops)"))); }
                                Err(_) => {
                                    let _ = reply.send(Ok("restarting without a peer to take over".into()));
                                    restart_now(&vip, vip_held).await;
                                }
                            }
                        } else {
                            let _ = reply.send(Ok("restarting".into()));
                            restart_now(&vip, vip_held).await;
                        }
                    }
                    HaCommand::SetPersist(value, reply) => {
                        ha_state.persist_override = value;
                        election.persist = value.unwrap_or(cfg.persist);
                        // Setting the policy explicitly ends a manual hold, so
                        // "off" / "config default" really resumes preemption.
                        election.hold = false;
                        let r = ha_state.save(&cfg.state_path).map_err(|e| e.to_string());
                        let _ = reply.send(r);
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("HA shutting down; releasing the VIP");
                if vip_held {
                    if let Err(e) = vip.down().await { error!(error = %e, "cannot release the VIP"); }
                }
                std::process::exit(0);
            }
        }

        let now = now_ms();
        let peer = alive_peer(&last_peer, now, cfg.dead_after_ms);
        let before = election.role;
        let gateway_ok = *gw_rx.borrow();
        let mut after = election.tick(now, peer.as_ref(), gateway_ok && now >= vip_fault_until_ms);

        // Move the VIP before announcing the new role, so a peer that reacts
        // to our Standby heartbeat never finds the address still ours.
        let want_vip = after == Role::Active;
        if want_vip != vip_held {
            let r = if want_vip { vip.up().await } else { vip.down().await };
            match r {
                Ok(()) => vip_held = want_vip,
                Err(e) if want_vip => {
                    error!(error = %e, "cannot add the VIP; entering Fault");
                    vip_fault_until_ms = now + HANDOVER_TIMEOUT_MS;
                    after = election.tick(now, peer.as_ref(), false);
                    reason = "VIP add failed".into();
                }
                Err(e) => error!(error = %e, "cannot remove the VIP"),
            }
        }
        if before != after && reason.is_empty() {
            reason = match (&peer, after) {
                (_, Role::Fault) => "gateway unreachable".into(),
                (None, Role::Active) => "peer not responding".into(),
                (Some(p), Role::Active) if p.handover_to.as_deref() == Some(cfg.node_name.as_str()) => {
                    format!("handover from {}", p.node)
                }
                (Some(_), Role::Standby) if election.handover_target().is_some() => "handing over to peer".into(),
                _ => "election".into(),
            };
        }

        if before != after {
            info!(from = ?before, to = ?after, %reason, "HA role change");
        }

        seq += 1;
        let hb = Heartbeat {
            node: cfg.node_name.clone(),
            boot_id,
            seq,
            ts_ms: now,
            role: after,
            weight: cfg.weight,
            persist: election.persist,
            hold: election.hold,
            handover_to: election.handover_target().map(|(t, _)| t.to_owned()),
            handover_manual: election.handover_target().is_some_and(|(_, m)| m),
            takeover_request: election.takeover_requested(now),
            config_hash,
        };
        if let Err(e) = sock.send_to(&encode(&key, &hb), peer_addr).await {
            // Expected while the peer host is down (ICMP unreachable).
            tracing::debug!(error = %e, "HA heartbeat send failed");
        }

        state.ha.status.send_modify(|s| {
            s.role = after;
            s.persist = election.persist;
            s.persist_source = if ha_state.persist_override.is_some() { "override" } else { "config" };
            s.hold = election.hold;
            s.vip_held = vip_held;
            s.gateway_ok = gateway_ok;
            s.handover_to = hb.handover_to.clone();
            s.peer = last_peer.as_ref().map(|lp| PeerStatus {
                node: lp.hb.node.clone(),
                ip: cfg.peer_ip,
                alive: now.saturating_sub(lp.at_ms) < cfg.dead_after_ms,
                role: lp.hb.role,
                weight: lp.hb.weight,
                persist: lp.hb.persist,
                hold: lp.hb.hold,
                last_seen_ms_ago: now.saturating_sub(lp.at_ms),
                config_hash: lp.hb.config_hash,
            });
            if before != after {
                s.transitions.push_front(Transition { ts_ms: now, from: before, to: after, reason: reason.clone() });
                s.transitions.truncate(TRANSITION_LOG_LEN);
            }
        });
        if before != after {
            ha_state.transitions = state.ha.status.borrow().transitions.clone();
            if let Err(e) = ha_state.save(&cfg.state_path) {
                warn!(error = %e, "cannot save HA state");
            }
        }

        // Services start once on the first Active (see `main::services`)
        // and are never stopped in place: a node that leaves Active restarts
        // into a clean Standby, which drops every Basestation, peer and SIP
        // session at once so they reconnect to the new Active node. A node
        // handing over first keeps heartbeating until the peer has taken
        // over (or the handover timed out).
        was_active |= after == Role::Active && vip_held;
        if election.handover_target().is_none() {
            if apply_pending {
                // Handover done (or timed out): restart to load the new config.
                restart_now(&vip, vip_held).await;
            }
            if was_active && after != Role::Active {
                warn!(role = ?after, "left Active: restarting into Standby");
                restart_now(&vip, vip_held).await;
            }
        }
    }
}

async fn restart_now(vip: &Vip, vip_held: bool) {
    if vip_held {
        if let Err(e) = vip.down().await { error!(error = %e, "cannot release the VIP"); }
    }
    crate::restart_process();
}

fn alive_peer(last: &Option<LastPeer>, now_ms: u64, dead_after_ms: u64) -> Option<PeerView> {
    last.as_ref()
        .filter(|lp| now_ms.saturating_sub(lp.at_ms) < dead_after_ms)
        .map(|lp| PeerView::from(&lp.hb))
}

fn rand_u64() -> u64 {
    let b = uuid::Uuid::new_v4().into_bytes();
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// SIGTERM/SIGINT, so a clean stop releases the VIP. (kill -9 cannot be
/// caught: the next start, or the peer's takeover, cleans up instead.)
fn signal_stream() -> Result<mpsc::Receiver<()>> {
    let (tx, rx) = mpsc::channel(1);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::spawn(async move {
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            let _ = tx.send(()).await;
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = tx.send(()).await;
    });
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTEN: u64 = 2000;

    fn peer(node: &str, role: Role, weight: u32) -> PeerView {
        PeerView {
            node: node.into(),
            role,
            weight,
            persist: false,
            hold: false,
            handover_to: None,
            handover_manual: false,
            takeover_request: false,
        }
    }

    fn running(node: &str, weight: u32, role: Role) -> Election {
        let mut e = Election::new(node, weight, false, 0, LISTEN);
        e.role = role;
        e
    }

    #[test]
    fn init_waits_then_takes_over_when_alone() {
        let mut e = Election::new("a", 100, false, 0, LISTEN);
        assert_eq!(e.tick(500, None, true), Role::Init);
        assert_eq!(e.tick(LISTEN, None, true), Role::Active);
    }

    #[test]
    fn init_defers_to_an_active_peer() {
        let mut e = Election::new("a", 200, false, 0, LISTEN);
        assert_eq!(e.tick(100, Some(&peer("b", Role::Active, 100)), true), Role::Standby);
    }

    #[test]
    fn higher_weight_wins_when_both_standby() {
        let mut a = running("a", 200, Role::Standby);
        let mut b = running("b", 100, Role::Standby);
        assert_eq!(a.tick(0, Some(&peer("b", Role::Standby, 100)), true), Role::Active);
        assert_eq!(b.tick(0, Some(&peer("a", Role::Standby, 200)), true), Role::Standby);
    }

    #[test]
    fn equal_weight_breaks_tie_by_name() {
        let mut b = running("b", 100, Role::Standby);
        assert_eq!(b.tick(0, Some(&peer("a", Role::Standby, 100)), true), Role::Active);
    }

    #[test]
    fn standby_takes_over_when_peer_dies() {
        let mut b = running("b", 100, Role::Standby);
        assert_eq!(b.tick(0, None, true), Role::Active);
    }

    #[test]
    fn active_hands_over_to_returning_higher_weight_peer() {
        let mut b = running("b", 100, Role::Active);
        assert_eq!(b.tick(0, Some(&peer("a", Role::Standby, 200)), true), Role::Standby);
        assert_eq!(b.handover_target(), Some(("a", false)));
        // a sees the handover and takes over, without hold.
        let mut a = running("a", 200, Role::Standby);
        let mut pv = peer("b", Role::Standby, 100);
        pv.handover_to = Some("a".into());
        assert_eq!(a.tick(0, Some(&pv), true), Role::Active);
        assert!(!a.hold);
        // b clears the handover once a is Active, and stays Standby.
        assert_eq!(b.tick(10, Some(&peer("a", Role::Active, 200)), true), Role::Standby);
        assert_eq!(b.handover_target(), None);
    }

    #[test]
    fn persist_blocks_preemption() {
        let mut b = running("b", 100, Role::Active);
        b.persist = true;
        assert_eq!(b.tick(0, Some(&peer("a", Role::Standby, 200)), true), Role::Active);
        // and a, as Standby, waits for b.
        let mut a = running("a", 200, Role::Standby);
        let mut pv = peer("b", Role::Active, 100);
        pv.persist = true;
        assert_eq!(a.tick(0, Some(&pv), true), Role::Standby);
    }

    #[test]
    fn manual_make_standby_hands_over_with_hold() {
        let mut a = running("a", 200, Role::Active);
        a.request_standby(Some(&peer("b", Role::Standby, 100)), 0).unwrap();
        assert_eq!(a.role, Role::Standby);
        assert_eq!(a.handover_target(), Some(("b", true)));

        let mut b = running("b", 100, Role::Standby);
        let mut pv = peer("a", Role::Standby, 200);
        pv.handover_to = Some("b".into());
        pv.handover_manual = true;
        assert_eq!(b.tick(0, Some(&pv), true), Role::Active);
        assert!(b.hold);

        // a (higher weight) does not preempt b while b holds.
        assert_eq!(a.tick(10, Some(&PeerView { hold: true, ..peer("b", Role::Active, 100) }), true), Role::Standby);
        // and b keeps Active against a Standby higher-weight peer.
        assert_eq!(b.tick(20, Some(&peer("a", Role::Standby, 200)), true), Role::Active);
    }

    #[test]
    fn manual_make_active_on_standby_requests_takeover() {
        let mut b = running("b", 100, Role::Standby);
        b.request_active(Some(&peer("a", Role::Active, 200)), 0).unwrap();
        assert!(b.takeover_requested(1));
        // a sees the request and hands over (manual).
        let mut a = running("a", 200, Role::Active);
        let mut pv = peer("b", Role::Standby, 100);
        pv.takeover_request = true;
        assert_eq!(a.tick(0, Some(&pv), true), Role::Standby);
        assert_eq!(a.handover_target(), Some(("b", true)));
    }

    #[test]
    fn takeover_request_expires() {
        let mut b = running("b", 100, Role::Standby);
        b.request_active(Some(&peer("a", Role::Active, 200)), 0).unwrap();
        b.tick(HANDOVER_TIMEOUT_MS, Some(&peer("a", Role::Active, 200)), true);
        assert!(!b.takeover_requested(HANDOVER_TIMEOUT_MS));
    }

    #[test]
    fn handover_times_out_if_peer_never_acts() {
        let mut a = running("a", 200, Role::Active);
        a.request_standby(Some(&peer("b", Role::Standby, 100)), 0).unwrap();
        assert_eq!(a.tick(100, Some(&peer("b", Role::Standby, 100)), true), Role::Standby);
        // After the timeout the normal rules apply again: a is preferred.
        assert_eq!(a.tick(HANDOVER_TIMEOUT_MS, Some(&peer("b", Role::Standby, 100)), true), Role::Active);
    }

    #[test]
    fn manual_commands_are_refused_when_they_cannot_work() {
        let mut a = running("a", 200, Role::Active);
        assert!(a.request_standby(None, 0).is_err(), "no peer to hand over to");
        assert!(a.request_active(None, 0).is_err(), "already active");
        let mut b = running("b", 100, Role::Standby);
        assert!(b.request_active(None, 0).is_err(), "peer gone");
        assert!(b.request_standby(None, 0).is_err(), "not active");
    }

    #[test]
    fn split_brain_lower_rank_steps_down() {
        let mut a = running("a", 200, Role::Active);
        let mut b = running("b", 100, Role::Active);
        assert_eq!(a.tick(0, Some(&peer("b", Role::Active, 100)), true), Role::Active);
        assert_eq!(b.tick(0, Some(&peer("a", Role::Active, 200)), true), Role::Standby);
    }

    #[test]
    fn split_brain_persist_outranks_weight() {
        let mut a = running("a", 200, Role::Active);
        let mut pv = peer("b", Role::Active, 100);
        pv.persist = true;
        assert_eq!(a.tick(0, Some(&pv), true), Role::Standby);
    }

    #[test]
    fn gateway_loss_faults_and_recovery_rejoins() {
        let mut a = running("a", 200, Role::Active);
        assert_eq!(a.tick(0, Some(&peer("b", Role::Standby, 100)), false), Role::Fault);
        // b sees a in Fault and takes over.
        let mut b = running("b", 100, Role::Standby);
        assert_eq!(b.tick(0, Some(&peer("a", Role::Fault, 200)), true), Role::Active);
        // a recovers; b is Active and a preempts through handover, not a grab.
        assert_eq!(a.tick(10, Some(&peer("b", Role::Active, 100)), true), Role::Standby);
    }

    #[test]
    fn heartbeat_round_trips_and_rejects_tampering() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");
        let hb = Heartbeat {
            node: "a".into(), boot_id: 1, seq: 1, ts_ms: 1000, role: Role::Active, weight: 200,
            persist: false, hold: false, handover_to: None, handover_manual: false,
            takeover_request: false, config_hash: 7,
        };
        let mut wire = encode(&key, &hb);
        assert_eq!(decode(&key, &wire), Some(hb));
        let other = hmac::Key::new(hmac::HMAC_SHA256, b"other");
        assert_eq!(decode(&other, &wire), None);
        wire[2] ^= 1;
        assert_eq!(decode(&key, &wire), None);
    }

    #[test]
    fn replay_guard_drops_old_and_stale() {
        let mut g = ReplayGuard::default();
        let mut hb = Heartbeat {
            node: "a".into(), boot_id: 1, seq: 5, ts_ms: 100_000, role: Role::Active, weight: 1,
            persist: false, hold: false, handover_to: None, handover_manual: false,
            takeover_request: false, config_hash: 0,
        };
        assert!(g.accept(&hb, 100_000));
        assert!(!g.accept(&hb, 100_000), "same seq");
        hb.seq = 6;
        assert!(!g.accept(&hb, 100_000 + MAX_CLOCK_SKEW_MS + 1), "stale");
        hb.boot_id = 2;
        hb.seq = 1;
        assert!(g.accept(&hb, 100_000), "restart resets seq");
    }

    #[test]
    fn state_file_round_trips() {
        let dir = std::env::temp_dir().join(format!("ha-state-{}", rand_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ha-state.json");
        assert_eq!(HaState::load(&path), HaState::default());
        let s = HaState { persist_override: Some(true), ..HaState::default() };
        s.save(&path).unwrap();
        assert_eq!(HaState::load(&path), s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
