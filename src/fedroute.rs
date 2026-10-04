//! Federation routing helpers.
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
use std::time::{Duration, Instant};
use uuid::Uuid;

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
