//! Federation routing: the loop-safe route exchange between brew-servers, and
//! de-duplication of calls and SDS that reach a server more than once.
//!
//! Negotiation. Loop-safe federation is agreed per peer link at connect time,
//! only between servers that both enable `[federation] loop_safe`: the
//! dialling side sends `X-Brew-Federation: 1` and its `X-Brew-Server-Id` on
//! the WebSocket upgrade, and the accepting side answers with its own in the
//! `101`. Anyone else -- an older brew-server, another Brew server, a
//! Basestation -- ignores the headers and does not echo them, so its link
//! stays a plain one. `FedState::links` holds the negotiated links; nothing of
//! class `protocol::CLASS_FEDERATION` is ever sent on any other connection.
//!
//! Route table. On a negotiated link registrations do not travel as relayed
//! SUB messages but as path-vector route adverts (`FED_ROUTE`/`FED_WITHDRAW`):
//! the ISSI, its registration clock at the origin server (`reg`, a hybrid
//! logical clock -- see `FedState::tick`), the servers it crossed (`path`,
//! sender first, origin last) and its groups. Each server keeps every
//! neighbour's current offer (`FedState::rib_in`) next to its own local
//! registrations and picks, per ISSI, the origin with the newest registration
//! (tie: higher server id) and the shortest path to it (`select`). Only that
//! choice -- the effective route -- is kept in `Inner::subscribers` and
//! `Inner::group_clients`, so call, SDS, SIP and SMS Center routing need no
//! change; and only a change of it is advertised on (`publish`), with this
//! server's id put in front. Nobody accepts a path holding its own id, so
//! adverts cannot loop whatever the topology (ring, full mesh, redundant
//! links), and when a link drops (`state::cleanup_client`) every ISSI routed
//! or offered over it fails over to the next best offer or is withdrawn. A
//! legacy peer link (an older server, or `loop_safe = false`) still gets SUB
//! messages, derived from the same effective table, and whatever it sends
//! counts as registered at this server -- so such a peer must hang off the
//! mesh by a single link: a cycle through it is not loop-safe.
//!
//! Call/SDS de-duplication: in any federation topology with more than one
//! path between two servers (a ring, a mesh, two links between the same pair)
//! the same GROUP_TX, private SETUP_REQUEST or SDS header can reach a server
//! more than once, over different peer links. Without a check the second copy
//! would take the call over (new owner, forwarded again) and could circulate
//! forever. Each copy is keyed by (uuid, source ISSI): a talker change inside
//! a group call reuses the uuid with another source ISSI and must still be
//! accepted.

use crate::protocol::{self, CLASS_FEDERATION, FED_ROUTE, FED_WITHDRAW};
use crate::state::{AppState, ClientId, ClientMode, Inner, Subscriber};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Request (and `101` response) header offering (accepting) loop-safe
/// federation; its value is the version, currently 1.
pub const X_BREW_FEDERATION: &str = "X-Brew-Federation";
/// This server's id, exactly 16 hex digits (see `FedState::self_id`).
pub const X_BREW_SERVER_ID: &str = "X-Brew-Server-Id";

/// Most servers a route may cross, origin included: a longer advert is not
/// passed on, which also bounds how long a withdrawn route can be chased
/// around a ring.
pub const MAX_PATH: usize = 16;
/// An advert registered more than this far ahead of our own clock is refused
/// (taken as a withdrawal of that link's offer): it would win every
/// comparison, and an ISSI roaming away from a server whose clock is wrong
/// would stay stuck there.
pub const MAX_FUTURE_MS: u64 = 86_400_000;

/// Where an effective route leads (`Subscriber::route`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    /// Registration clock at the origin when the ISSI last (re)registered.
    pub reg: u64,
    /// Servers to cross, next hop first and origin last; empty for an ISSI
    /// registered here (by a Basestation, Terminal or legacy peer link).
    pub path: Vec<u64>,
}

/// One neighbour's current offer for an ISSI (a received `FED_ROUTE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    pub reg: u64,
    /// `path[0]` is the neighbour itself, the last entry the origin.
    pub path: Vec<u64>,
    pub groups: Vec<u32>,
}

/// Loop-safe federation state, in `Inner`.
#[derive(Debug)]
pub struct FedState {
    /// This server's id: random, non-zero and new on every start. Never
    /// persisted or configured -- a cloned VM or config file would duplicate
    /// it, and each server would then silently reject the other's routes as
    /// its own. A restart closes every link, so nothing keeps the old id.
    pub self_id: u64,
    /// Hybrid logical clock for local registrations (`tick`).
    clock: u64,
    /// Negotiated (loop-safe) peer links -> neighbour server id.
    pub links: HashMap<ClientId, u64>,
    /// Latest advert per ISSI per negotiated link (each neighbour's current offer).
    pub rib_in: HashMap<u32, HashMap<ClientId, Advert>>,
}

impl Default for FedState {
    fn default() -> Self {
        let self_id = loop {
            let id = Uuid::new_v4().as_u64_pair().0;
            if id != 0 { break id; }
        };
        Self { self_id, clock: 0, links: HashMap::new(), rib_in: HashMap::new() }
    }
}

impl FedState {
    /// Registration clock for a local (re)registration: wall-clock ms, but
    /// always above every registration seen so far (`observe`), so one made
    /// here after a remote one wins even when the other server's clock runs
    /// ahead. Clock skew only orders truly concurrent registrations of the
    /// same ISSI on two servers (keep the servers on NTP).
    pub fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1).max(crate::telemetry::now_ms());
        self.clock
    }

    /// Takes an accepted remote registration clock into account.
    pub fn observe(&mut self, reg: u64) {
        self.clock = self.clock.max(reg);
    }
}

/// `X-Brew-Server-Id` value: 16 lowercase hex digits.
pub fn format_server_id(id: u64) -> String {
    format!("{id:016x}")
}

/// Parses an `X-Brew-Server-Id` value: exactly 16 hex digits.
pub fn parse_server_id(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.len() != 16 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}

/// Whether an `X-Brew-Federation` value offers (accepts) a version we speak.
pub fn federation_offered(value: Option<&str>) -> bool {
    value.and_then(|v| v.trim().parse::<u32>().ok()).is_some_and(|v| v >= 1)
}

// ─── Wire format ─────────────────────────────────────────────────────────

/// One `CLASS_FEDERATION` message, little-endian:
///
/// - `FED_WITHDRAW`: `0xfe 0x00 issi:u32` -- this link no longer offers a
///   route to `issi`.
/// - `FED_ROUTE`: `0xfe 0x01 issi:u32 reg:u64 n:u8 path:u64[n] groups:u32[..]`
///   -- `issi` is reachable via the sender, `path[0]` being the sender and
///   `path[n-1]` the origin, `1 <= n <= MAX_PATH`; the groups run to the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FedMessage {
    Withdraw { issi: u32 },
    Route { issi: u32, advert: Advert },
    /// A type this version does not know (from a newer peer): ignored.
    Unknown(u8),
}

pub fn build_withdraw(issi: u32) -> Vec<u8> {
    let mut out = vec![CLASS_FEDERATION, FED_WITHDRAW];
    out.extend_from_slice(&issi.to_le_bytes());
    out
}

pub fn build_route(issi: u32, reg: u64, path: &[u64], groups: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(15 + 8 * path.len() + 4 * groups.len());
    out.extend_from_slice(&[CLASS_FEDERATION, FED_ROUTE]);
    out.extend_from_slice(&issi.to_le_bytes());
    out.extend_from_slice(&reg.to_le_bytes());
    out.push(path.len() as u8);
    for id in path { out.extend_from_slice(&id.to_le_bytes()); }
    for g in groups { out.extend_from_slice(&g.to_le_bytes()); }
    out
}

/// Parses a `CLASS_FEDERATION` message received from neighbour `nbr_id`.
/// A route must start at that neighbour and cross no server twice.
pub fn parse(raw: &[u8], nbr_id: u64) -> Result<FedMessage, &'static str> {
    let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().expect("checked length"));
    let u64_at = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().expect("checked length"));
    match raw.get(1).copied() {
        None => Err("too short"),
        Some(FED_WITHDRAW) if raw.len() == 6 => Ok(FedMessage::Withdraw { issi: u32_at(2) }),
        Some(FED_WITHDRAW) => Err("FED_WITHDRAW of wrong length"),
        Some(FED_ROUTE) => {
            if raw.len() < 15 {
                return Err("FED_ROUTE too short");
            }
            let n = raw[14] as usize;
            if n == 0 || n > MAX_PATH {
                return Err("FED_ROUTE path length out of range");
            }
            let groups_at = 15 + 8 * n;
            if raw.len() < groups_at || !(raw.len() - groups_at).is_multiple_of(4) {
                return Err("FED_ROUTE of wrong length");
            }
            let path: Vec<u64> = (0..n).map(|i| u64_at(15 + 8 * i)).collect();
            if path[0] != nbr_id {
                return Err("FED_ROUTE path does not start at the server that sent it");
            }
            if path.iter().enumerate().any(|(i, id)| path[..i].contains(id)) {
                return Err("FED_ROUTE path crosses a server twice");
            }
            let groups = raw[groups_at..].chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes"))).collect();
            Ok(FedMessage::Route { issi: u32_at(2), advert: Advert { reg: u64_at(6), path, groups } })
        }
        Some(other) => Ok(FedMessage::Unknown(other)),
    }
}

// ─── Route selection ─────────────────────────────────────────────────────

/// Outcome of `select` for one ISSI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// The local registration.
    Local,
    /// The offer received over this negotiated link.
    Remote(ClientId),
    Unreachable,
}

/// Picks the effective route for an ISSI, the same way on every server: the
/// origin with the newest registration wins (tie: the higher server id), and
/// among the offers from that origin the shortest path (tie: the lower
/// neighbour id, then link). The second step ignores `reg`, so a
/// re-registration at the origin does not move the next hop around: its new
/// clock and groups arrive over the shortest path anyway. `local` is the
/// clock of this server's own registration, if any.
pub fn select(
    self_id: u64,
    local: Option<u64>,
    links: &HashMap<ClientId, u64>,
    cands: Option<&HashMap<ClientId, Advert>>,
) -> Choice {
    let offers = || cands.into_iter().flat_map(|c| c.iter());
    let newest_remote = offers().filter_map(|(_, a)| a.path.last().map(|origin| (a.reg, *origin))).max();
    let origin = match newest_remote {
        Some((reg, origin)) if local.is_none_or(|own| (own, self_id) < (reg, origin)) => origin,
        _ if local.is_some() => return Choice::Local,
        _ => return Choice::Unreachable,
    };
    offers()
        .filter(|(_, a)| a.path.last() == Some(&origin))
        .min_by_key(|(link, a)| (a.path.len(), links.get(*link).copied().unwrap_or(u64::MAX), **link))
        .map_or(Choice::Unreachable, |(link, _)| Choice::Remote(*link))
}

// ─── Effective table ─────────────────────────────────────────────────────

/// Whether two effective entries route the same way (link, groups, route).
fn same(a: Option<&Subscriber>, b: Option<&Subscriber>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.client_id == b.client_id && a.groups == b.groups && a.route == b.route,
        _ => false,
    }
}

fn sorted(groups: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut v: Vec<u32> = groups.into_iter().collect();
    v.sort_unstable();
    v
}

/// Replaces the effective route of `issi` (`None`: unreachable). The one
/// writer of `inner.subscribers` and of the subscriber part of
/// `inner.group_clients` (the SIP bridge adds its own virtual members), which
/// it keeps consistent: a connection is in a group's set exactly while one of
/// the ISSIs routed over it is in that group. So an ISSI moving off a peer
/// link leaves the link in every group another ISSI behind it still uses.
pub fn set_effective(inner: &mut Inner, issi: u32, new: Option<Subscriber>) {
    let old = match &new {
        Some(n) => inner.subscribers.insert(issi, n.clone()),
        None => inner.subscribers.remove(&issi),
    };
    if let Some(old) = old {
        for g in &old.groups {
            let still_used = inner.subscribers.values().any(|s| s.client_id == old.client_id && s.groups.contains(g));
            if still_used { continue; }
            if let Some(members) = inner.group_clients.get_mut(g) {
                members.remove(&old.client_id);
                if members.is_empty() { inner.group_clients.remove(g); }
            }
        }
    }
    if let Some(n) = new {
        for g in n.groups {
            inner.group_clients.entry(g).or_default().insert(n.client_id);
        }
    }
}

/// Re-runs `select` for `issi` between its local registration (if the
/// effective entry is one) and the neighbours' offers, and applies the result.
/// True when the effective route changed.
pub fn reroute(inner: &mut Inner, issi: u32) -> bool {
    let current = inner.subscribers.get(&issi).cloned();
    let local = current.clone().filter(|s| !inner.fed.links.contains_key(&s.client_id));
    let cands = inner.fed.rib_in.get(&issi);
    let new = match select(inner.fed.self_id, local.as_ref().map(|s| s.route.reg), &inner.fed.links, cands) {
        Choice::Local => local.clone(),
        Choice::Remote(link) => cands.and_then(|c| c.get(&link)).map(|a| Subscriber {
            client_id: link,
            groups: a.groups.iter().copied().collect(),
            mode: ClientMode::Peer,
            route: Route { reg: a.reg, path: a.path.clone() },
        }),
        Choice::Unreachable => None,
    };
    if same(current.as_ref(), new.as_ref()) {
        return false;
    }
    if let (Some(_), Some(origin)) = (&local, new.as_ref().and_then(|n| n.route.path.last())) {
        // Last writer wins, as it always has, now network-wide: the ISSI
        // registered again elsewhere (it roamed), so the stale local
        // registration is dropped.
        info!(issi, origin = %format_server_id(*origin), "registration superseded by a newer one at another server");
    }
    set_effective(inner, issi, new);
    true
}

/// What a negotiated link to neighbour `nbr_id` is told about `issi` after
/// its effective route became `eff`: the route with this server in front,
/// or a withdrawal when there is none, when it runs over that very link
/// (poison reverse), when the neighbour is already on it (it would refuse
/// it; also covers a second link to the same server) or when it would grow
/// past `MAX_PATH`.
pub fn fed_update(self_id: u64, nbr_link: ClientId, nbr_id: u64, issi: u32, eff: Option<&Subscriber>) -> Vec<u8> {
    match eff {
        Some(e) if e.client_id != nbr_link && !e.route.path.contains(&nbr_id) && e.route.path.len() < MAX_PATH => {
            let path: Vec<u64> = std::iter::once(self_id).chain(e.route.path.iter().copied()).collect();
            build_route(issi, e.route.reg, &path, &sorted(e.groups.iter().copied()))
        }
        _ => build_withdraw(issi),
    }
}

/// The SUB messages a legacy peer link `peer` gets when the effective entry
/// of `issi` goes from `old` to `new`. It sees an entry only while it does
/// not run over itself (split horizon), and gets the difference: what it
/// sends back is local to this server, so it is never echoed what it said.
pub fn legacy_updates(issi: u32, old: Option<&Subscriber>, new: Option<&Subscriber>, peer: ClientId) -> Vec<Vec<u8>> {
    let before = old.filter(|o| o.client_id != peer);
    let after = new.filter(|n| n.client_id != peer);
    let sub = |t, groups: &[u32]| protocol::build_subscriber_message(t, issi, groups);
    let mut out = Vec::new();
    match (before, after) {
        (None, None) => {}
        // Gone -- unless it is `peer` itself that registered it now.
        (Some(_), None) => if new.is_none() { out.push(sub(protocol::SUB_DEREGISTER, &[])) },
        (None, Some(n)) => {
            out.push(sub(protocol::SUB_REGISTER, &[]));
            if !n.groups.is_empty() { out.push(sub(protocol::SUB_AFFILIATE, &sorted(n.groups.iter().copied()))); }
        }
        (Some(o), Some(n)) => {
            let added = sorted(n.groups.difference(&o.groups).copied());
            let removed = sorted(o.groups.difference(&n.groups).copied());
            if o.route.reg != n.route.reg {
                // A new registration: an older server keeps the groups it
                // had across a REGISTER, so the full set follows.
                out.push(sub(protocol::SUB_REGISTER, &[]));
                if !n.groups.is_empty() { out.push(sub(protocol::SUB_AFFILIATE, &sorted(n.groups.iter().copied()))); }
            } else if !added.is_empty() {
                out.push(sub(protocol::SUB_AFFILIATE, &added));
            }
            if !removed.is_empty() { out.push(sub(protocol::SUB_DEAFFILIATE, &removed)); }
        }
    }
    out
}

/// Queues the updates for a change of `issi`'s effective entry from `old` to
/// what `inner.subscribers` holds now, on every peer link. Done with the lock
/// held: the sends never block, and every link gets every change in the order
/// the table went through them. Basestations and Terminals get nothing, as
/// before. True when a registration appeared (new entry, or a new `reg`):
/// the SMS Center's cue to deliver what it holds for the ISSI.
pub fn publish(inner: &Inner, issi: u32, old: Option<&Subscriber>) -> bool {
    let new = inner.subscribers.get(&issi);
    if same(old, new) {
        return false;
    }
    for (link, client) in &inner.clients {
        if client.mode != ClientMode::Peer {
            continue;
        }
        match inner.fed.links.get(link) {
            Some(&nbr_id) => { let _ = client.tx.send(fed_update(inner.fed.self_id, *link, nbr_id, issi, new)); }
            None => for msg in legacy_updates(issi, old, new, *link) { let _ = client.tx.send(msg); },
        }
    }
    new.is_some_and(|n| old.is_none_or(|o| o.route.reg != n.route.reg))
}

/// The full table a newly attached peer `link` starts from (see
/// `federation::attach_client`): every effective route it may use, as
/// adverts on a negotiated link, as `SUB_REGISTER` + `SUB_AFFILIATE` on a
/// legacy one.
pub fn sync_messages(inner: &Inner, link: ClientId) -> Vec<Vec<u8>> {
    let issis = sorted(inner.subscribers.keys().copied());
    match inner.fed.links.get(&link) {
        Some(&nbr_id) => issis.iter()
            .map(|issi| fed_update(inner.fed.self_id, link, nbr_id, *issi, inner.subscribers.get(issi)))
            .filter(|msg| msg[1] == FED_ROUTE)
            .collect(),
        None => issis.iter().flat_map(|issi| legacy_updates(*issi, None, inner.subscribers.get(issi), link)).collect(),
    }
}

/// Drops `link`'s offer for `issi`; true if it had one.
fn withdraw_offer(inner: &mut Inner, issi: u32, link: ClientId) -> bool {
    let Some(offers) = inner.fed.rib_in.get_mut(&issi) else { return false };
    let had = offers.remove(&link).is_some();
    if offers.is_empty() {
        inner.fed.rib_in.remove(&issi);
    }
    had
}

/// Handles a `CLASS_FEDERATION` message from `source` (see `router::handle_packet`).
pub async fn handle(state: &Arc<AppState>, source: ClientId, raw: &[u8]) {
    let registered = {
        let mut inner = state.inner.write().await;
        let Some(&nbr_id) = inner.fed.links.get(&source) else {
            // Only possible if a proxy dropped the headers from the 101 alone.
            warn!(%source, "federation message on a link that did not negotiate loop-safe mode; dropped");
            return;
        };
        let msg = match parse(raw, nbr_id) {
            Ok(msg) => msg,
            Err(why) => {
                warn!(%source, why, bytes = raw.len(), "malformed federation message dropped");
                return;
            }
        };
        match msg {
            FedMessage::Route { issi, advert } => {
                let old = inner.subscribers.get(&issi).cloned();
                let too_new = advert.reg > crate::telemetry::now_ms().saturating_add(MAX_FUTURE_MS);
                if too_new {
                    warn!(%source, issi, reg = advert.reg, "route advert registered over a day in the future (peer clock wrong?); taken as a withdrawal");
                }
                if too_new || advert.path.contains(&inner.fed.self_id) {
                    // A path through ourselves is a loop: that link has no
                    // usable route to the ISSI.
                    withdraw_offer(&mut inner, issi, source);
                } else {
                    inner.fed.observe(advert.reg);
                    inner.fed.rib_in.entry(issi).or_default().insert(source, advert);
                }
                // Passed on only when our own choice changed.
                let changed = reroute(&mut inner, issi);
                (changed && publish(&inner, issi, old.as_ref())).then_some(issi)
            }
            FedMessage::Withdraw { issi } => {
                let old = inner.subscribers.get(&issi).cloned();
                let changed = withdraw_offer(&mut inner, issi, source) && reroute(&mut inner, issi);
                (changed && publish(&inner, issi, old.as_ref())).then_some(issi)
            }
            FedMessage::Unknown(t) => {
                debug!(%source, msg_type = t, "unknown federation message type ignored");
                None
            }
        }
    };
    if let Some(issi) = registered {
        crate::router::subscriber_registered(state, issi);
    }
}

// ─── Call/SDS de-duplication ─────────────────────────────────────────────

/// How long a (call/SDS uuid, source ISSI) is remembered after it was
/// accepted, changed talker or ended: a copy of it arriving over another peer
/// link within this window is a duplicate, not a new transmission.
pub const CALL_DEDUP_WINDOW: Duration = Duration::from_secs(5);

/// Whether a GROUP_TX, SETUP_REQUEST or SDS header `id` from talker `src`,
/// arriving over peer link `link`, is a copy of one already accepted over
/// another link. Only meant for peer links: a Basestation's own traffic is
/// never second-guessed.
pub fn is_duplicate(inner: &Inner, id: Uuid, src: u32, link: ClientId, now: Instant) -> bool {
    // 1. Exact: the live call/SDS already has this talker, accepted over another link.
    let live = inner.calls.get(&id).map(|c| (c.source_issi, c.owner))
        .or_else(|| inner.sds_routes.get(&id).map(|r| (r.source_issi, r.source_client)));
    if matches!(live, Some((s, owner)) if s == src && owner != link) {
        return true;
    }
    // 2. Recent: a late copy of a turn/call/SDS that just changed talker or ended.
    matches!(inner.recent_calls.get(&(id, src)),
        Some((first, at)) if *first != link && now.duration_since(*at) < CALL_DEDUP_WINDOW)
}

/// Remembers that (`id`, `src`) was accepted from `link` (or ended there).
pub fn note_call(inner: &mut Inner, id: Uuid, src: u32, link: ClientId, now: Instant) {
    inner.recent_calls.insert((id, src), (link, now));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ActiveCall, CallKind, SdsRoute};
    use std::collections::HashSet;

    fn group_call(owner: ClientId, src: u32) -> ActiveCall {
        ActiveCall {
            kind: CallKind::Group, owner, source_issi: src, destination: 91, priority: 0,
            peers: HashSet::new(), started_at: Instant::now(), last_activity_ms: ActiveCall::new_activity(),
        }
    }

    #[test]
    fn server_ids_are_random_non_zero_and_round_trip() {
        let (a, b) = (FedState::default().self_id, FedState::default().self_id);
        assert!(a != 0 && b != 0 && a != b);
        assert_eq!(format_server_id(0x00a1_b2c3_d4e5_f607), "00a1b2c3d4e5f607");
        assert_eq!(parse_server_id(&format_server_id(a)), Some(a));
        assert_eq!(parse_server_id("00A1B2C3D4E5F607"), Some(0x00a1_b2c3_d4e5_f607));
        for bad in ["", "a1b2c3d4e5f607", "00a1b2c3d4e5f6071", "00a1b2c3d4e5f60g", "+0a1b2c3d4e5f607"] {
            assert_eq!(parse_server_id(bad), None, "{bad:?}");
        }
        assert!(federation_offered(Some("1")) && federation_offered(Some(" 2 ")));
        assert!(!federation_offered(Some("0")) && !federation_offered(Some("yes")) && !federation_offered(None));
    }

    #[test]
    fn route_and_withdraw_round_trip() {
        let wire = build_route(1001, 0x0102_0304_0506_0708, &[7, 8, 9], &[91, 92]);
        assert_eq!(wire.len(), 15 + 3 * 8 + 2 * 4);
        assert_eq!(&wire[..2], &[0xfe, 0x01]);
        let advert = Advert { reg: 0x0102_0304_0506_0708, path: vec![7, 8, 9], groups: vec![91, 92] };
        assert_eq!(parse(&wire, 7), Ok(FedMessage::Route { issi: 1001, advert }));
        // No groups is fine too.
        assert!(matches!(parse(&build_route(1001, 1, &[7], &[]), 7), Ok(FedMessage::Route { .. })));
        assert_eq!(build_withdraw(1001), vec![0xfe, 0x00, 0xe9, 0x03, 0x00, 0x00]);
        assert_eq!(parse(&build_withdraw(1001), 7), Ok(FedMessage::Withdraw { issi: 1001 }));
        assert_eq!(parse(&[0xfe, 0x7f, 1, 2, 3], 7), Ok(FedMessage::Unknown(0x7f)));
    }

    #[test]
    fn malformed_federation_messages_are_refused() {
        let good = build_route(1001, 5, &[7, 8], &[91]);
        assert!(parse(&good[..14], 7).is_err(), "header cut short");
        assert!(parse(&good[..good.len() - 1], 7).is_err(), "groups not a multiple of 4");
        assert!(parse(&good[..15 + 8], 7).is_err(), "path cut short");
        let mut zero = build_route(1001, 5, &[7], &[]);
        zero[14] = 0;
        assert!(parse(&zero, 7).is_err(), "empty path");
        let long: Vec<u64> = (1..=MAX_PATH as u64 + 1).collect();
        assert!(parse(&build_route(1001, 5, &long, &[]), 1).is_err(), "path over MAX_PATH");
        assert!(parse(&build_route(1001, 5, &long[..MAX_PATH], &[]), 1).is_ok(), "MAX_PATH itself is fine");
        assert!(parse(&build_route(1001, 5, &[7, 8, 7], &[]), 7).is_err(), "server twice on the path");
        assert!(parse(&build_route(1001, 5, &[8, 7], &[]), 7).is_err(), "not sent by its first server");
        assert!(parse(&[0xfe, 0x00, 1, 2, 3], 7).is_err(), "short withdraw");
        assert!(parse(&[0xfe, 0x00, 1, 2, 3, 4, 5], 7).is_err(), "long withdraw");
        assert!(parse(&[0xfe], 7).is_err());
    }

    #[test]
    fn clock_ticks_past_everything_observed() {
        let mut fed = FedState::default();
        let now = crate::telemetry::now_ms();
        let a = fed.tick();
        assert!(a >= now);
        assert!(fed.tick() > a, "strictly increasing within the same millisecond");
        fed.observe(now + 3_600_000);
        assert!(fed.tick() > now + 3_600_000, "a peer clock running ahead does not make ours lose");
        fed.observe(1);
        assert!(fed.tick() > now + 3_600_000, "never goes back");
    }

    fn offers(list: &[(ClientId, u64, &[u64])]) -> HashMap<ClientId, Advert> {
        list.iter().map(|(link, reg, path)| (*link, Advert { reg: *reg, path: path.to_vec(), groups: vec![] })).collect()
    }

    #[test]
    fn select_prefers_the_newest_registration_then_the_higher_origin() {
        let (l1, l2) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let links = HashMap::from([(l1, 10), (l2, 20)]);
        // Origin 30 registered later than origin 40, even though its path is longer.
        let cands = offers(&[(l1, 200, &[10, 30]), (l2, 100, &[20, 40])]);
        assert_eq!(select(5, None, &links, Some(&cands)), Choice::Remote(l1));
        // Same clock: the higher origin id wins.
        let cands = offers(&[(l1, 100, &[10, 30]), (l2, 100, &[20, 40])]);
        assert_eq!(select(5, None, &links, Some(&cands)), Choice::Remote(l2));
        // A local registration competes like any origin.
        assert_eq!(select(50, Some(100), &links, Some(&cands)), Choice::Local);
        assert_eq!(select(5, Some(100), &links, Some(&cands)), Choice::Remote(l2));
        assert_eq!(select(5, Some(101), &links, Some(&cands)), Choice::Local);
        assert_eq!(select(5, Some(1), &links, None), Choice::Local);
        assert_eq!(select(5, None, &links, None), Choice::Unreachable);
    }

    #[test]
    fn select_takes_the_shortest_path_to_the_winning_origin() {
        let (l1, l2, l3) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let links = HashMap::from([(l1, 10), (l2, 20), (l3, 30)]);
        // The longer path carries a newer clock: still the shorter one, as
        // the origin is the same (no next-hop flapping on a re-register).
        let cands = offers(&[(l1, 200, &[10, 11, 40]), (l2, 100, &[20, 40])]);
        assert_eq!(select(5, None, &links, Some(&cands)), Choice::Remote(l2));
        // Equal length: the lower neighbour id, then the lower link.
        let cands = offers(&[(l3, 100, &[30, 40]), (l2, 100, &[20, 40])]);
        assert_eq!(select(5, None, &links, Some(&cands)), Choice::Remote(l2));
        let (m1, m2) = (Uuid::from_u128(8), Uuid::from_u128(9));
        let twin = HashMap::from([(m1, 10), (m2, 10)]);
        let cands = offers(&[(m2, 100, &[10, 40]), (m1, 100, &[10, 40])]);
        assert_eq!(select(5, None, &twin, Some(&cands)), Choice::Remote(m1));
    }

    fn sub(client: ClientId, groups: &[u32], reg: u64, path: &[u64]) -> Subscriber {
        Subscriber { client_id: client, groups: groups.iter().copied().collect(), mode: ClientMode::Peer, route: Route { reg, path: path.to_vec() } }
    }

    #[test]
    fn fed_update_follows_the_advertising_rules() {
        let (n, other) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let via_other = sub(other, &[92, 91], 100, &[30, 40]);
        assert_eq!(fed_update(5, n, 10, 1001, Some(&via_other)), build_route(1001, 100, &[5, 30, 40], &[91, 92]));
        assert_eq!(fed_update(5, n, 10, 1001, Some(&sub(other, &[], 100, &[]))), build_route(1001, 100, &[5], &[]), "a local one");
        assert_eq!(fed_update(5, n, 10, 1001, None), build_withdraw(1001));
        assert_eq!(fed_update(5, n, 10, 1001, Some(&sub(n, &[], 100, &[10]))), build_withdraw(1001), "poison reverse");
        assert_eq!(fed_update(5, n, 30, 1001, Some(&via_other)), build_withdraw(1001), "the neighbour is on the path");
        let full: Vec<u64> = (100..100 + MAX_PATH as u64).collect();
        assert_eq!(fed_update(5, n, 10, 1001, Some(&sub(other, &[], 1, &full))), build_withdraw(1001), "would exceed MAX_PATH");
        assert!(matches!(parse(&fed_update(5, n, 10, 1001, Some(&sub(other, &[], 1, &full[1..]))), 5), Ok(FedMessage::Route { .. })));
    }

    #[test]
    fn legacy_updates_send_only_what_the_peer_link_does_not_know() {
        let (p, a, b) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let m = |t, g: &[u32]| protocol::build_subscriber_message(t, 1001, g);
        use protocol::{SUB_AFFILIATE as AFF, SUB_DEAFFILIATE as DEAFF, SUB_DEREGISTER as DEREG, SUB_REGISTER as REG};
        assert!(legacy_updates(1001, None, None, p).is_empty());
        assert_eq!(legacy_updates(1001, None, Some(&sub(a, &[], 1, &[])), p), vec![m(REG, &[])]);
        assert_eq!(legacy_updates(1001, None, Some(&sub(a, &[92, 91], 1, &[])), p), vec![m(REG, &[]), m(AFF, &[91, 92])]);
        assert_eq!(legacy_updates(1001, Some(&sub(a, &[91], 1, &[])), None, p), vec![m(DEREG, &[])]);
        // Group changes of the same registration.
        assert_eq!(legacy_updates(1001, Some(&sub(a, &[91, 92], 1, &[])), Some(&sub(a, &[92, 93], 1, &[])), p),
            vec![m(AFF, &[93]), m(DEAFF, &[91])]);
        // Moved to another link, same registration: nothing changes for p.
        assert!(legacy_updates(1001, Some(&sub(a, &[91], 1, &[9])), Some(&sub(b, &[91], 1, &[8, 9])), p).is_empty());
        // A new registration: the full group set follows.
        assert_eq!(legacy_updates(1001, Some(&sub(a, &[91, 92], 1, &[])), Some(&sub(b, &[92], 2, &[])), p),
            vec![m(REG, &[]), m(AFF, &[92]), m(DEAFF, &[91])]);
        // Never echoed what p itself registered, nor told to drop it.
        assert!(legacy_updates(1001, None, Some(&sub(p, &[91], 1, &[])), p).is_empty());
        assert!(legacy_updates(1001, Some(&sub(a, &[91], 1, &[])), Some(&sub(p, &[91], 2, &[])), p).is_empty());
        assert!(legacy_updates(1001, Some(&sub(p, &[91], 1, &[])), None, p).is_empty());
        // ...but told when the ISSI is now reached through us instead.
        assert_eq!(legacy_updates(1001, Some(&sub(p, &[], 1, &[])), Some(&sub(a, &[], 2, &[])), p), vec![m(REG, &[])]);
    }

    #[test]
    fn set_effective_keeps_a_link_in_groups_its_other_issis_use() {
        let (link, bs) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut inner = Inner::default();
        set_effective(&mut inner, 1001, Some(sub(link, &[91], 1, &[])));
        set_effective(&mut inner, 1002, Some(sub(link, &[91, 92], 1, &[])));
        // 1001 moves to a Basestation: the link still carries 1002 in 91.
        set_effective(&mut inner, 1001, Some(sub(bs, &[91], 2, &[])));
        assert_eq!(inner.group_clients[&91], HashSet::from([link, bs]));
        set_effective(&mut inner, 1002, None);
        assert_eq!(inner.group_clients[&91], HashSet::from([bs]));
        assert!(!inner.group_clients.contains_key(&92), "an empty group goes");
        assert_eq!(inner.subscribers.len(), 1);
    }

    #[test]
    fn reroute_fails_over_and_supersedes() {
        let (l1, l2, bs) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let mut inner = Inner::default();
        inner.fed.links = HashMap::from([(l1, 10), (l2, 20)]);
        inner.fed.rib_in.insert(1001, offers(&[(l1, 100, &[10, 40]), (l2, 100, &[20, 30, 40])]));
        assert!(reroute(&mut inner, 1001));
        assert_eq!(inner.subscribers[&1001].client_id, l1);
        assert!(!reroute(&mut inner, 1001), "nothing changed");
        inner.fed.rib_in.get_mut(&1001).unwrap().remove(&l1);
        assert!(reroute(&mut inner, 1001));
        assert_eq!(inner.subscribers[&1001].route, Route { reg: 100, path: vec![20, 30, 40] }, "failed over");
        // Registered here again, later: local wins and stays.
        let reg = inner.fed.tick();
        set_effective(&mut inner, 1001, Some(Subscriber { client_id: bs, groups: HashSet::new(), mode: ClientMode::Basestation, route: Route { reg, path: vec![] } }));
        assert!(!reroute(&mut inner, 1001));
        // A newer registration elsewhere supersedes it.
        inner.fed.rib_in.insert(1001, offers(&[(l2, reg + 1, &[20, 30])]));
        assert!(reroute(&mut inner, 1001));
        assert_eq!(inner.subscribers[&1001].client_id, l2);
        inner.fed.rib_in.clear();
        assert!(reroute(&mut inner, 1001));
        assert!(inner.subscribers.is_empty(), "the superseded local registration is gone");
    }

    #[test]
    fn live_call_with_same_talker_from_another_link_is_a_duplicate() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let id = Uuid::new_v4();
        let now = Instant::now();
        let mut inner = Inner::default();
        inner.calls.insert(id, group_call(a, 1001));
        assert!(is_duplicate(&inner, id, 1001, b, now));
        assert!(!is_duplicate(&inner, id, 1001, a, now), "a repeat over the owning link is not a copy");
        assert!(!is_duplicate(&inner, id, 1002, b, now), "another talker is a talker change");
        assert!(!is_duplicate(&inner, Uuid::new_v4(), 1001, b, now));
    }

    #[test]
    fn live_sds_with_same_sender_from_another_link_is_a_duplicate() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let id = Uuid::new_v4();
        let mut inner = Inner::default();
        inner.sds_routes.insert(id, SdsRoute {
            source_client: a, targets: HashSet::new(), source_issi: 1001, destination: 2002,
            created_at: Instant::now(), store_offline: false,
        });
        assert!(is_duplicate(&inner, id, 1001, b, Instant::now()));
        assert!(!is_duplicate(&inner, id, 1001, a, Instant::now()));
    }

    #[test]
    fn recent_entry_drops_late_copies_within_the_window_only() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        let mut inner = Inner::default();
        note_call(&mut inner, id, 1001, a, t0);
        assert!(is_duplicate(&inner, id, 1001, b, t0 + Duration::from_secs(1)));
        assert!(!is_duplicate(&inner, id, 1001, a, t0 + Duration::from_secs(1)));
        assert!(!is_duplicate(&inner, id, 1001, b, t0 + CALL_DEDUP_WINDOW));
    }
}

