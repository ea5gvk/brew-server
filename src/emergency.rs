//! Active emergencies: Basestation emergency alarms (telemetry) and live
//! emergency calls (priority 15) on the Brew channel, as one list. It feeds the
//! dashboard ribbon, the red marker on the MS map and -- pushed as a
//! `SERVICE_EMERGENCY` message -- every connected Tetra Dispatch console.

use crate::protocol;
use crate::state::AppState;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One active emergency.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Emergency {
    pub issi: u32,
    /// Group or called ISSI of an emergency call; `None` for a Basestation alarm
    /// whose radio is not in a call.
    pub destination: Option<u32>,
    /// Basestation that reported the alarm (telemetry); `None` for a call.
    pub bts: Option<String>,
    /// "alarm" (Basestation telemetry) or "call" (priority-15 call on the Brew channel).
    pub kind: &'static str,
    pub blacklisted: bool,
}

/// Active emergencies. A Basestation alarm whose radio has a live call is one
/// emergency, not two: the alarm entry takes the called group.
pub async fn snapshot(state: &Arc<AppState>) -> Vec<Emergency> {
    let mut out: Vec<Emergency> = Vec::new();
    for s in state.telemetry.read().await.stations.values() {
        for issi in &s.emergencies {
            out.push(Emergency { issi: *issi, destination: None, bts: Some(s.id.clone()), kind: "alarm", blacklisted: state.is_blocked(*issi) });
        }
    }
    let inner = state.inner.read().await;
    for call in inner.calls.values().filter(|c| c.priority >= crate::router::EMERGENCY_PRIORITY) {
        out.push(Emergency {
            issi: call.source_issi, destination: Some(call.destination), bts: None, kind: "call",
            blacklisted: state.is_blocked(call.source_issi),
        });
    }
    let calls: Vec<(u32, Option<u32>)> = out.iter().filter(|e| e.kind == "call").map(|e| (e.issi, e.destination)).collect();
    for e in out.iter_mut().filter(|e| e.kind == "alarm") {
        if let Some((_, dest)) = calls.iter().find(|(issi, _)| *issi == e.issi) { e.destination = *dest; }
    }
    let alarmed: std::collections::HashSet<u32> = out.iter().filter(|e| e.kind == "alarm").map(|e| e.issi).collect();
    out.retain(|e| e.kind != "call" || !alarmed.contains(&e.issi));
    out.sort_by_key(|e| (e.issi, e.kind));
    out.dedup_by(|a, b| a.issi == b.issi && a.kind == b.kind && a.destination == b.destination && a.bts == b.bts);
    out
}

/// `SERVICE_EMERGENCY` message: `{"emergencies":[{"issi":N,"dest":G|null}, ...]}`,
/// the full current list (empty clears a console's ribbon).
pub fn build_message(list: &[Emergency]) -> Vec<u8> {
    let items: Vec<serde_json::Value> = list.iter().map(|e| serde_json::json!({"issi": e.issi, "dest": e.destination})).collect();
    protocol::build_service(protocol::SERVICE_EMERGENCY, &serde_json::json!({"emergencies": items}).to_string())
}

/// What `push_if_due` remembers between calls.
pub struct PushState {
    last: Vec<(u32, Option<u32>)>,
    last_sent: Instant,
}

impl Default for PushState {
    fn default() -> Self {
        Self { last: Vec::new(), last_sent: Instant::now() - Duration::from_secs(60) }
    }
}

/// Pushes the emergency list to every dispatch console when it changed, and
/// again every few seconds while any is active, so a console that connects late
/// (or misses one) catches up. True when a message went out.
pub async fn push_if_due(state: &Arc<AppState>, st: &mut PushState) -> bool {
    let list = snapshot(state).await;
    let key: Vec<(u32, Option<u32>)> = list.iter().map(|e| (e.issi, e.destination)).collect();
    let due = key != st.last || (!key.is_empty() && st.last_sent.elapsed() >= Duration::from_secs(5));
    if !due { return false; }
    st.last = key;
    st.last_sent = Instant::now();
    let msg = build_message(&list);
    let inner = state.inner.read().await;
    for id in &inner.consoles {
        if let Some(c) = inner.clients.get(id) { let _ = c.tx.send(msg.clone()); }
    }
    true
}

pub async fn run(state: Arc<AppState>) {
    let mut st = PushState::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        push_if_due(&state, &mut st).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ActiveCall, CallKind, Client, ClientMode};
    use tokio::sync::mpsc;

    fn call(source: u32, dest: u32, priority: u8) -> ActiveCall {
        ActiveCall {
            kind: CallKind::Group, owner: uuid::Uuid::new_v4(), source_issi: source, destination: dest, priority,
            peers: Default::default(), started_at: Instant::now(), last_activity_ms: ActiveCall::new_activity(),
        }
    }

    #[tokio::test]
    async fn snapshot_merges_an_alarm_with_its_call_and_ignores_ordinary_calls() {
        let state = AppState::for_test();
        state.inner.write().await.calls.insert(uuid::Uuid::new_v4(), call(4013, 91, 15));
        state.inner.write().await.calls.insert(uuid::Uuid::new_v4(), call(4014, 92, 0));
        state.inner.write().await.calls.insert(uuid::Uuid::new_v4(), call(4015, 93, 15)); // a relayed call, no alarm here
        {
            let mut t = state.telemetry.write().await;
            t.add_test_station("bts2", None, "bts2");
            let st = t.stations.get_mut("bts2").unwrap();
            st.emergencies.insert(4013);
            st.emergencies.insert(4020); // alarm, radio not in a call
        }
        let list = snapshot(&state).await;
        let got: Vec<(u32, Option<u32>, &str)> = list.iter().map(|e| (e.issi, e.destination, e.kind)).collect();
        assert_eq!(got, vec![(4013, Some(91), "alarm"), (4015, Some(93), "call"), (4020, None, "alarm")]);
    }

    #[tokio::test]
    async fn consoles_are_pushed_the_list_on_change_and_while_active() {
        let state = AppState::for_test();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let console = uuid::Uuid::new_v4();
        {
            let mut inner = state.inner.write().await;
            inner.clients.insert(console, Client { tx, mode: ClientMode::Basestation, version: crate::protocol::ConnVersion::V0, version_announced: true, remote_addr: None, connected_at_ms: 0, username: None });
            inner.consoles.insert(console);
        }
        let mut st = PushState::default();
        let drain = |rx: &mut mpsc::UnboundedReceiver<Vec<u8>>| std::iter::from_fn(|| rx.try_recv().ok()).collect::<Vec<_>>();
        let json = |m: &Vec<u8>| -> serde_json::Value {
            assert_eq!(&m[..2], &[protocol::CLASS_SERVICE, protocol::SERVICE_EMERGENCY]);
            assert_eq!(m.last(), Some(&0));
            serde_json::from_slice(&m[2..m.len() - 1]).unwrap()
        };

        // Nothing active and nothing changed: nothing is sent.
        assert!(!push_if_due(&state, &mut st).await);
        assert!(drain(&mut rx).is_empty());

        // An alarm comes up: pushed.
        {
            let mut t = state.telemetry.write().await;
            t.add_test_station("bts2", None, "bts2");
            t.stations.get_mut("bts2").unwrap().emergencies.insert(4013);
        }
        assert!(push_if_due(&state, &mut st).await);
        assert_eq!(json(&drain(&mut rx)[0])["emergencies"], serde_json::json!([{"issi": 4013, "dest": null}]));
        assert!(!push_if_due(&state, &mut st).await, "unchanged and recently sent");

        // Cleared: an empty list goes out so the console drops its ribbon.
        state.telemetry.write().await.stations.get_mut("bts2").unwrap().emergencies.clear();
        assert!(push_if_due(&state, &mut st).await);
        assert_eq!(json(&drain(&mut rx)[0])["emergencies"], serde_json::json!([]));
    }
}
