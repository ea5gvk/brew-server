//! Federation routing helpers.
//!
//! Loop-safe federation is negotiated per peer link at connect time, only
//! between servers that both enable `[federation] loop_safe`: the dialling
//! side sends `X-Brew-Federation: 1` and its `X-Brew-Server-Id` on the
//! WebSocket upgrade, and the accepting side answers with its own in the
//! `101`. Anyone else -- an older brew-server, another Brew server, a
//! Basestation -- ignores the headers and does not echo them, so its link
//! stays a plain one. `FedState::links` holds the negotiated links.
//!
//! Call/SDS de-duplication: in any federation topology with more than one
//! path between two servers (a ring, a mesh, two links between the same pair)
//! the same GROUP_TX, private SETUP_REQUEST or SDS header can reach a server
//! more than once, over different peer links. Without a check the second copy
//! would take the call over (new owner, forwarded again) and could circulate
//! forever. Each copy is keyed by (uuid, source ISSI): a talker change inside
//! a group call reuses the uuid with another source ISSI and must still be
//! accepted.

use crate::state::{ClientId, Inner};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Request (and `101` response) header offering (accepting) loop-safe
/// federation; its value is the version, currently 1.
pub const X_BREW_FEDERATION: &str = "X-Brew-Federation";
/// This server's id, exactly 16 hex digits (see `FedState::self_id`).
pub const X_BREW_SERVER_ID: &str = "X-Brew-Server-Id";

/// Loop-safe federation state, in `Inner`.
#[derive(Debug)]
pub struct FedState {
    /// This server's id: random, non-zero and new on every start. Never
    /// persisted or configured -- a cloned VM or config file would duplicate
    /// it, and each server would then silently reject the other's routes as
    /// its own. A restart closes every link, so nothing keeps the old id.
    pub self_id: u64,
    /// Negotiated (loop-safe) peer links -> neighbour server id.
    pub links: HashMap<ClientId, u64>,
}

impl Default for FedState {
    fn default() -> Self {
        let self_id = loop {
            let id = Uuid::new_v4().as_u64_pair().0;
            if id != 0 { break id; }
        };
        Self { self_id, links: HashMap::new() }
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
