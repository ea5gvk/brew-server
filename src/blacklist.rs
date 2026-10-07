//! Editing the ISSI blacklist, from the dashboard or from a Tetra Dispatch
//! console over its Brew link, and keeping the consoles' view of it current.

use crate::protocol;
use crate::state::AppState;
use std::sync::Arc;

pub enum ApplyError {
    Invalid,
    Save(anyhow::Error),
}

/// Blocks or unblocks an ISSI on the running server at once and writes the
/// config file without a restart (a restart would drop every call), then tells
/// the consoles. `by` names who asked, for the log.
pub async fn apply(state: &Arc<AppState>, issi: u32, blocked: bool, by: &str) -> Result<(), ApplyError> {
    if issi == 0 || issi > 0xFF_FFFF {
        return Err(ApplyError::Invalid);
    }
    state.set_blocked(issi, blocked);
    tracing::warn!(issi, blocked, by, "ISSI blacklist changed");
    let cfg = state.config_snapshot();
    crate::CONFIG_WRITE_APPLIED_LIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    let saved = crate::dashboard::save_config(state, &cfg).await;
    if saved.is_err() {
        crate::CONFIG_WRITE_APPLIED_LIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    push_to_consoles(state).await;
    saved.map_err(ApplyError::Save)
}

/// Whether a connection may edit the blacklist: a dispatch console whose Brew
/// username is in `[blacklist] console_users`.
async fn may_edit(state: &Arc<AppState>, client: crate::state::ClientId) -> bool {
    let inner = state.inner.read().await;
    inner.consoles.contains(&client)
        && inner.clients.get(&client).and_then(|c| c.username.as_ref())
            .is_some_and(|u| state.config.blacklist.console_users.iter().any(|a| a == u))
}

fn message(list: &[u32], can_edit: bool) -> Vec<u8> {
    protocol::build_service(protocol::SERVICE_BLACKLIST, &serde_json::json!({"blacklist": list, "can_edit": can_edit}).to_string())
}

fn error_message(error: &str) -> Vec<u8> {
    protocol::build_service(protocol::SERVICE_BLACKLIST, &serde_json::json!({"error": error}).to_string())
}

/// Sends every connected console the blacklist, and whether it may edit it.
pub async fn push_to_consoles(state: &Arc<AppState>) {
    let list = state.blocked_list();
    let consoles: Vec<crate::state::ClientId> = state.inner.read().await.consoles.iter().copied().collect();
    for id in consoles {
        let can_edit = may_edit(state, id).await;
        if let Some(c) = state.inner.read().await.clients.get(&id) {
            let _ = c.tx.send(message(&list, can_edit));
        }
    }
}

/// A `SERVICE_BLACKLIST_CMD` from `source`: `{"action":"block"|"unblock","issi":N}`.
/// Only a dispatch console allowed by `console_users` is obeyed; anyone else is
/// told so.
pub async fn handle_command(state: &Arc<AppState>, source: crate::state::ClientId, json: &str) {
    let reply = |msg: Vec<u8>| async move {
        if let Some(c) = state.inner.read().await.clients.get(&source) { let _ = c.tx.send(msg); }
    };
    if !may_edit(state, source).await {
        tracing::warn!(%source, "blacklist command refused: not an authorised dispatch console");
        reply(error_message("not authorised to edit the blacklist")).await;
        return;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        reply(error_message("malformed command")).await;
        return;
    };
    let issi = v["issi"].as_u64().and_then(|i| u32::try_from(i).ok()).unwrap_or(0);
    let blocked = match v["action"].as_str() {
        Some("block") => true,
        Some("unblock") => false,
        _ => {
            reply(error_message("unknown action")).await;
            return;
        }
    };
    let by = state.inner.read().await.clients.get(&source).and_then(|c| c.username.clone()).unwrap_or_default();
    match apply(state, issi, blocked, &format!("console {by}")).await {
        Ok(()) => {}
        Err(ApplyError::Invalid) => reply(error_message("ISSI must be 1-16777215")).await,
        Err(ApplyError::Save(e)) => reply(error_message(&format!("applied, but saving the config failed: {e}"))).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Client, ClientMode};
    use tokio::sync::mpsc;

    fn state_with(console_users: &[&str]) -> (Arc<AppState>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("brew-bl-{}.toml", uuid::Uuid::new_v4()));
        let mut c = crate::config::Config::default();
        c.storage.enabled = false;
        c.sms_center.enabled = false;
        c.blacklist.console_users = console_users.iter().map(|s| s.to_string()).collect();
        (Arc::new(AppState::new(c, path.clone()).0), path)
    }

    async fn connect(state: &Arc<AppState>, user: &str, console: bool) -> (crate::state::ClientId, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = uuid::Uuid::new_v4();
        let mut inner = state.inner.write().await;
        inner.clients.insert(id, Client { tx, mode: ClientMode::Basestation, version: protocol::ConnVersion::V0, version_announced: true, remote_addr: None, connected_at_ms: 0, username: Some(user.into()) });
        if console { inner.consoles.insert(id); }
        (id, rx)
    }

    fn json(m: &[u8]) -> serde_json::Value {
        assert_eq!(&m[..2], &[protocol::CLASS_SERVICE, protocol::SERVICE_BLACKLIST]);
        serde_json::from_slice(&m[2..m.len() - 1]).unwrap()
    }

    fn drain(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    #[tokio::test]
    async fn an_authorised_console_can_block_and_unblock_and_all_consoles_hear_it() {
        let (state, path) = state_with(&["9990001"]);
        let (op, mut op_rx) = connect(&state, "9990001", true).await;
        let (_other, mut other_rx) = connect(&state, "9990002", true).await;

        handle_command(&state, op, r#"{"action":"block","issi":4013}"#).await;
        assert!(state.is_blocked(4013));
        assert_eq!(crate::config::Config::load(path.to_str().unwrap()).unwrap().blacklist.issis, vec![4013]);
        // Each console is told the list, and whether it may edit it.
        assert_eq!(json(&drain(&mut op_rx)[0]), serde_json::json!({"blacklist": [4013], "can_edit": true}));
        assert_eq!(json(&drain(&mut other_rx)[0]), serde_json::json!({"blacklist": [4013], "can_edit": false}));

        handle_command(&state, op, r#"{"action":"unblock","issi":4013}"#).await;
        assert!(!state.is_blocked(4013));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn other_users_and_non_consoles_are_refused() {
        let (state, path) = state_with(&["9990001"]);
        let (other, mut other_rx) = connect(&state, "9990002", true).await; // a console, not allowed
        let (bs, mut bs_rx) = connect(&state, "9990001", false).await; // allowed name, but not a console
        for (id, rx) in [(other, &mut other_rx), (bs, &mut bs_rx)] {
            handle_command(&state, id, r#"{"action":"block","issi":4013}"#).await;
            assert!(!state.is_blocked(4013));
            assert!(json(&drain(rx)[0])["error"].as_str().unwrap().contains("not authorised"));
        }
        // With no `console_users` configured, nobody can edit.
        let (state2, path2) = state_with(&[]);
        let (c, mut c_rx) = connect(&state2, "9990001", true).await;
        handle_command(&state2, c, r#"{"action":"block","issi":4013}"#).await;
        assert!(!state2.is_blocked(4013));
        assert!(json(&drain(&mut c_rx)[0]).get("error").is_some());
        // A bad request from an authorised console is answered, not applied.
        let (state3, path3) = state_with(&["9990001"]);
        let (c, mut c_rx) = connect(&state3, "9990001", true).await;
        for bad in ["not json", r#"{"action":"nuke","issi":1}"#, r#"{"action":"block","issi":0}"#] {
            handle_command(&state3, c, bad).await;
            assert!(json(&drain(&mut c_rx)[0]).get("error").is_some(), "{bad}");
        }
        assert!(state3.blocked_list().is_empty());
        for p in [path, path2, path3] { let _ = std::fs::remove_file(p); }
    }
}
