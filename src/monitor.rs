use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, VecDeque}, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord { pub uuid: Uuid, pub kind: String, pub source: u32, pub destination: u32, pub priority: u8, pub started_at_ms: u64, pub ended_at_ms: Option<u64>, pub voice_frames: u64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdsRecord { pub uuid: Uuid, pub source: u32, pub destination: u32, pub at_ms: u64, pub reports: u32 }
#[derive(Debug, Clone, Serialize)]
pub struct LiveEvent { pub event: String, pub at_ms: u64, pub data: serde_json::Value }
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot { pub connected_basestations: usize, pub subscribers: usize, pub groups: usize, pub active_calls: Vec<CallRecord>, pub recent_calls: Vec<CallRecord>, pub recent_sds: Vec<SdsRecord>, pub total_calls: u64, pub total_sds: u64, pub voice_frames: u64 }

#[derive(Default)] struct Inner { active: HashMap<Uuid, CallRecord>, calls: VecDeque<CallRecord>, sds: VecDeque<SdsRecord>, total_calls: u64, total_sds: u64, voice_frames: u64 }

pub struct Monitor { inner: RwLock<Inner>, tx: broadcast::Sender<LiveEvent>, store: Option<std::sync::Arc<crate::store::Store>> }
impl Monitor {
    pub fn new() -> Self { let (tx, _) = broadcast::channel(256); Self { inner: RwLock::new(Inner::default()), tx, store: None } }

    /// Creates a Monitor backed by an append-only store, replaying existing
    /// history from disk so counters and recent lists survive restarts.
    pub fn with_store(store: std::sync::Arc<crate::store::Store>) -> Self {
        let (tx, _) = broadcast::channel(256);
        let mut inner = Inner::default();
        if let Ok(records) = crate::store::Store::replay(store.path()) {
            for rec in records {
                apply_record(&mut inner, rec);
            }
            tracing::info!(path = %store.path().display(), calls = inner.total_calls, sds = inner.total_sds, "replayed persisted history");
        }
        Self { inner: RwLock::new(inner), tx, store: Some(store) }
    }

    /// Adds a history record replicated from the HA peer (already appended
    /// to the store by the caller) to the in-memory lists and counters.
    pub async fn ingest_replicated(&self, rec: crate::store::StoredRecord) {
        apply_record(&mut *self.inner.write().await, rec);
    }

    fn persist(&self, rec: &crate::store::StoredRecord) {
        if let Some(store) = &self.store {
            if let Err(e) = store.append(rec) {
                tracing::error!(error = %e, "failed to persist history record");
            }
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LiveEvent> { self.tx.subscribe() }
    pub fn emit(&self, event: &str, data: serde_json::Value) { let _ = self.tx.send(LiveEvent { event: event.into(), at_ms: now_ms(), data }); }
    pub async fn call_started(&self, uuid: Uuid, kind: &str, source: u32, destination: u32, priority: u8) {
        let rec = CallRecord { uuid, kind: kind.into(), source, destination, priority, started_at_ms: now_ms(), ended_at_ms: None, voice_frames: 0 };
        let mut i = self.inner.write().await; if i.active.insert(uuid, rec.clone()).is_none() { i.total_calls += 1; }
        drop(i); self.emit("call_started", serde_json::json!(rec));
    }
    pub async fn call_ended(&self, uuid: Uuid) { let mut i = self.inner.write().await; if let Some(mut r)=i.active.remove(&uuid) { r.ended_at_ms=Some(now_ms()); i.calls.push_front(r.clone()); while i.calls.len()>200 { i.calls.pop_back(); } drop(i); self.persist(&crate::store::StoredRecord::Call(r.clone())); self.emit("call_ended", serde_json::json!(r)); } }
    pub async fn voice_frame(&self, uuid: Uuid) { let mut i=self.inner.write().await; i.voice_frames+=1; if let Some(r)=i.active.get_mut(&uuid){r.voice_frames+=1;} }
    pub async fn sds(&self, uuid: Uuid, source: u32, destination: u32) { let r=SdsRecord{uuid,source,destination,at_ms:now_ms(),reports:0}; let mut i=self.inner.write().await; i.total_sds+=1; i.sds.push_front(r.clone()); while i.sds.len()>200{i.sds.pop_back();} drop(i); self.persist(&crate::store::StoredRecord::Sds(r.clone())); self.emit("sds",serde_json::json!(r)); }
    pub async fn sds_report(&self, uuid: Uuid) { let mut i=self.inner.write().await; if let Some(r)=i.sds.iter_mut().find(|r|r.uuid==uuid){r.reports+=1;} drop(i); self.persist(&crate::store::StoredRecord::SdsReport { uuid }); }
    pub async fn snapshot(&self, clients: usize, subscribers: usize, groups: usize) -> Snapshot { let i=self.inner.read().await; Snapshot{connected_basestations:clients,subscribers,groups,active_calls:i.active.values().cloned().collect(),recent_calls:i.calls.iter().take(50).cloned().collect(),recent_sds:i.sds.iter().take(50).cloned().collect(),total_calls:i.total_calls,total_sds:i.total_sds,voice_frames:i.voice_frames} }
}

/// Folds one persisted record into the in-memory history (startup replay and
/// HA replication).
fn apply_record(inner: &mut Inner, rec: crate::store::StoredRecord) {
    match rec {
        crate::store::StoredRecord::Call(r) => {
            inner.total_calls += 1;
            inner.voice_frames += r.voice_frames;
            inner.calls.push_front(r);
            while inner.calls.len() > 200 { inner.calls.pop_back(); }
        }
        crate::store::StoredRecord::Sds(r) => {
            inner.total_sds += 1;
            inner.sds.push_front(r);
            while inner.sds.len() > 200 { inner.sds.pop_back(); }
        }
        crate::store::StoredRecord::SdsReport { uuid } => {
            if let Some(r) = inner.sds.iter_mut().find(|r| r.uuid == uuid) { r.reports += 1; }
        }
        crate::store::StoredRecord::SdsTelemetry(_) => {}
    }
}

#[cfg(test)]
mod persist_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn history_survives_restart_via_store() {
        let path = std::env::temp_dir().join(format!("brew-mon-test-{}.bin", Uuid::new_v4().simple()));
        let uuid_call = Uuid::new_v4();
        let uuid_sds = Uuid::new_v4();
        {
            let store = Arc::new(crate::store::Store::open(&path).unwrap());
            let m = Monitor::with_store(store);
            m.call_started(uuid_call, "group", 90, 1001, 0).await;
            m.call_ended(uuid_call).await;
            m.sds(uuid_sds, 90, 100).await;
            m.sds_report(uuid_sds).await;
            let snap = m.snapshot(0, 0, 0).await;
            assert_eq!(snap.total_calls, 1);
            assert_eq!(snap.total_sds, 1);
        }
        // New Monitor over the same file must replay the history.
        {
            let store = Arc::new(crate::store::Store::open(&path).unwrap());
            let m = Monitor::with_store(store);
            let snap = m.snapshot(0, 0, 0).await;
            assert_eq!(snap.total_calls, 1, "call count restored");
            assert_eq!(snap.total_sds, 1, "sds count restored");
            assert_eq!(snap.recent_calls.len(), 1);
            assert_eq!(snap.recent_sds.len(), 1);
            assert_eq!(snap.recent_sds[0].reports, 1, "sds report replayed");
        }
        std::fs::remove_file(&path).ok();
    }
}
