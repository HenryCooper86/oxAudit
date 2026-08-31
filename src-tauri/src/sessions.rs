//! Session persistence: JSONL transcript per session + a `sessions.json`
//! index. Modeled on y-agent's `transcript.rs` (append-only, corrupt lines
//! skipped on read) with a lightweight metadata index instead of SQLite.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use tauri::Manager;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub title: String,
    pub auto_title: bool,
    pub created_at: String,
    pub updated_at: String,
    pub message_count: usize,
    pub project_path: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StoredToolRecord {
    pub tool_call_id: String,
    pub name: String,
    pub arguments: String,
    pub status: String,
    pub duration_ms: Option<u64>,
    pub result_preview: Option<String>,
}

/// Record of a compaction seam: the turn this message answers was generated
/// from a summary of `summarized_messages` earlier turns, reproduced verbatim
/// so the divider can be reconstructed after a reload.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CompactionMarker {
    pub summarized_messages: u32,
    pub summary: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StoredMessage {
    pub id: String,
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub tools: Vec<StoredToolRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Present when the conversation was compacted for the turn this message
    /// answers; the UI renders it as a seam divider, and it is never replayed
    /// into the prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction: Option<CompactionMarker>,
    pub at: String,
}

pub struct SessionStore {
    pub dir: PathBuf,
}

// Session commands construct lightweight stores on demand. A process-wide
// guard therefore protects every read-modify-write sequence, regardless of
// which command instance initiated it.
static SESSION_IO_LOCK: Mutex<()> = Mutex::new(());

fn lock_session_io() -> Result<MutexGuard<'static, ()>, String> {
    SESSION_IO_LOCK
        .lock()
        .map_err(|_| "session storage lock is unavailable".to_string())
}

impl SessionStore {
    pub fn new(app: &tauri::AppHandle) -> Result<Self, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("cannot resolve config dir: {e}"))?
            .join("sessions");
        crate::private_storage::ensure_private_dir(&dir)?;
        Ok(Self { dir })
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("sessions.json")
    }

    fn parse_session_id(id: &str) -> Result<uuid::Uuid, String> {
        uuid::Uuid::parse_str(id).map_err(|_| "invalid session id".to_string())
    }

    fn transcript_path(&self, id: &uuid::Uuid) -> PathBuf {
        self.dir.join(format!("{id}.jsonl"))
    }

    fn indexed_position(index: &[SessionInfo], id: &uuid::Uuid) -> Result<usize, String> {
        let trusted = id.to_string();
        index
            .iter()
            .position(|session| session.id == trusted)
            .ok_or_else(|| "session not found".to_string())
    }

    fn read_messages(&self, id: &uuid::Uuid) -> Result<Vec<StoredMessage>, String> {
        let content = match crate::private_storage::read_to_string(&self.transcript_path(id)) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("cannot read transcript: {error}")),
        };
        let mut out = Vec::new();
        for line in content.lines() {
            if let Ok(message) = serde_json::from_str::<StoredMessage>(line) {
                out.push(message);
            }
        }
        Ok(out)
    }

    fn load_index(&self) -> Result<Vec<SessionInfo>, String> {
        match crate::private_storage::read_to_string(&self.index_path()) {
            Ok(content) => serde_json::from_str(&content).map_err(|e| e.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(format!("cannot read session index: {error}")),
        }
    }

    fn save_index(&self, index: &[SessionInfo]) -> Result<(), String> {
        let content = serde_json::to_string_pretty(index).map_err(|e| e.to_string())?;
        crate::private_storage::atomic_write(&self.index_path(), content.as_bytes())
            .map_err(|error| format!("cannot write index: {error}"))
    }

    fn now() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    // ------------------------------------------------------------------ list
    pub fn list(&self) -> Result<Vec<SessionInfo>, String> {
        let _guard = lock_session_io()?;
        let mut index = self.load_index()?;
        index.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(index)
    }

    // ---------------------------------------------------------------- create
    pub fn create(
        &self,
        title: Option<String>,
        project_path: Option<String>,
    ) -> Result<SessionInfo, String> {
        let _guard = lock_session_io()?;
        let auto_title = title.is_none();
        let session_id = uuid::Uuid::new_v4();
        let info = SessionInfo {
            id: session_id.to_string(),
            title: title.unwrap_or_else(|| "New chat".into()),
            auto_title,
            created_at: Self::now(),
            updated_at: Self::now(),
            message_count: 0,
            project_path,
        };
        let mut index = self.load_index()?;
        index.push(info.clone());
        self.save_index(&index)?;
        // ensure the transcript file exists (empty)
        crate::private_storage::open_private_append(&self.transcript_path(&session_id))
            .map_err(|error| format!("cannot create transcript: {error}"))?;
        Ok(info)
    }

    // ------------------------------------------------------------ get_messages
    pub fn get_messages(&self, id: &str) -> Result<Vec<StoredMessage>, String> {
        let _guard = lock_session_io()?;
        let id = Self::parse_session_id(id)?;
        let index = self.load_index()?;
        Self::indexed_position(&index, &id)?;
        self.read_messages(&id)
    }

    // ----------------------------------------------------------------- append
    /// Append one message; updates metadata and auto-titles the session from
    /// its first user message. Returns the updated `SessionInfo`.
    pub fn append(&self, id: &str, msg: &StoredMessage) -> Result<SessionInfo, String> {
        let _guard = lock_session_io()?;
        let id = Self::parse_session_id(id)?;
        let mut index = self.load_index()?;
        let pos = Self::indexed_position(&index, &id)?;
        let mut f = crate::private_storage::open_private_append(&self.transcript_path(&id))
            .map_err(|error| format!("cannot open transcript: {error}"))?;
        let line = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        writeln!(f, "{line}").map_err(|e| format!("cannot append: {e}"))?;
        f.flush().ok();

        let mut info = index[pos].clone();
        info.updated_at = Self::now();
        info.message_count += 1;
        if info.auto_title && msg.role == "user" && info.message_count == 1 {
            info.title = make_title(&msg.content);
        }
        index[pos] = info.clone();
        self.save_index(&index)?;
        Ok(info)
    }

    // ----------------------------------------------------------------- rename
    pub fn rename(&self, id: &str, title: String) -> Result<(), String> {
        let _guard = lock_session_io()?;
        let id = Self::parse_session_id(id)?;
        let title = title.trim().to_string();
        if title.is_empty() {
            return Err("title cannot be empty".into());
        }
        let mut index = self.load_index()?;
        let pos = Self::indexed_position(&index, &id)?;
        let info = &mut index[pos];
        info.title = title;
        info.auto_title = false;
        self.save_index(&index)
    }

    // ----------------------------------------------------------------- delete
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let _guard = lock_session_io()?;
        let id = Self::parse_session_id(id)?;
        let mut index = self.load_index()?;
        let pos = Self::indexed_position(&index, &id)?;
        index.remove(pos);
        self.save_index(&index)?;
        let path = self.transcript_path(&id);
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot delete transcript: {error}")),
        }
        Ok(())
    }

    // --------------------------------------------------------------- truncate
    /// Keep only the first `keep` messages (rewind / clear).
    pub fn truncate(&self, id: &str, keep: usize) -> Result<(), String> {
        let _guard = lock_session_io()?;
        let id = Self::parse_session_id(id)?;
        let mut index = self.load_index()?;
        let pos = Self::indexed_position(&index, &id)?;
        let messages = self.read_messages(&id)?;
        let kept: Vec<&StoredMessage> = messages.iter().take(keep).collect();
        let kept_len = kept.len();
        let path = self.transcript_path(&id);
        let mut content = String::new();
        for m in &kept {
            content.push_str(&serde_json::to_string(m).map_err(|e| e.to_string())?);
            content.push('\n');
        }
        crate::private_storage::atomic_write(&path, content.as_bytes())
            .map_err(|error| format!("cannot truncate: {error}"))?;
        let info = &mut index[pos];
        info.message_count = kept_len;
        info.updated_at = Self::now();
        self.save_index(&index)
    }
}

/// Heuristic session title from the first user message.
fn make_title(content: &str) -> String {
    let collapsed: String = content.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.chars().count() <= 60 {
        trimmed.to_string()
    } else {
        let t: String = trimmed.chars().take(60).collect();
        format!("{t}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (SessionStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SessionStore {
            dir: dir.path().to_path_buf(),
        };
        (store, dir)
    }

    fn msg(id: &str, role: &str, content: &str) -> StoredMessage {
        StoredMessage {
            id: id.into(),
            role: role.into(),
            content: content.into(),
            tools: vec![],
            model: None,
            compaction: None,
            at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn traversal_ids_cannot_read_or_truncate_neighboring_jsonl_files() {
        let directory = tempfile::tempdir().expect("temporary session parent");
        let sessions = directory.path().join("sessions");
        fs::create_dir(&sessions).expect("sessions directory");
        let store = SessionStore { dir: sessions };
        let outside = directory.path().join("outside.jsonl");
        let original = serde_json::to_string(&msg("outside", "user", "private record"))
            .expect("stored message");
        fs::write(&outside, format!("{original}\n")).expect("outside fixture");

        assert!(store.get_messages("../outside").is_err());
        assert!(store.truncate("../outside", 0).is_err());
        assert_eq!(
            fs::read_to_string(&outside).expect("outside file survives"),
            format!("{original}\n")
        );
    }

    #[test]
    fn an_unindexed_uuid_is_rejected_before_transcript_mutation() {
        let (store, _directory) = temp_store();
        let unknown = uuid::Uuid::new_v4().to_string();
        let transcript = store.transcript_path(&uuid::Uuid::parse_str(&unknown).unwrap());
        fs::write(&transcript, "must remain\n").expect("orphan transcript fixture");

        assert!(store.truncate(&unknown, 0).is_err());
        assert_eq!(
            fs::read_to_string(transcript).expect("orphan survives"),
            "must remain\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn session_index_and_transcripts_are_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;

        let (store, _directory) = temp_store();
        let session = store.create(None, None).expect("session");
        let id = uuid::Uuid::parse_str(&session.id).expect("uuid");

        let index_mode = fs::metadata(store.index_path())
            .expect("index metadata")
            .permissions()
            .mode()
            & 0o777;
        let transcript_mode = fs::metadata(store.transcript_path(&id))
            .expect("transcript metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(index_mode, 0o600);
        assert_eq!(transcript_mode, 0o600);
    }

    #[test]
    fn concurrent_appends_do_not_lose_session_metadata_updates() {
        use std::sync::{Arc, Barrier};

        const APPENDS: usize = 32;
        let (store, _directory) = temp_store();
        let session = store
            .create(Some("Concurrent".into()), None)
            .expect("session");
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(APPENDS));
        let mut workers = Vec::new();

        for index in 0..APPENDS {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let session_id = session.id.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .append(
                        &session_id,
                        &msg(&index.to_string(), "assistant", "concurrent message"),
                    )
                    .expect("append");
            }));
        }

        for worker in workers {
            worker.join().expect("worker");
        }

        let info = store.list().expect("session index");
        assert_eq!(info[0].message_count, APPENDS);
        assert_eq!(
            store.get_messages(&session.id).expect("messages").len(),
            APPENDS
        );
    }

    #[test]
    fn create_append_list_roundtrip() {
        let (store, _d) = temp_store();
        let s = store.create(None, Some("/tmp/proj".into())).unwrap();
        assert_eq!(s.message_count, 0);
        store
            .append(&s.id, &msg("1", "user", "Analyze CVE-2024-1234 please"))
            .unwrap();
        store
            .append(&s.id, &msg("2", "assistant", "Here is the analysis…"))
            .unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].message_count, 2);
        assert_eq!(list[0].project_path.as_deref(), Some("/tmp/proj"));
        // auto-title from first user message
        assert!(list[0].title.starts_with("Analyze CVE-2024-1234"));

        let msgs = store.get_messages(&s.id).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].content, "Here is the analysis…");
    }

    #[test]
    fn explicit_title_never_overwritten() {
        let (store, _d) = temp_store();
        let s = store.create(Some("My Research".into()), None).unwrap();
        store
            .append(&s.id, &msg("1", "user", "first user message"))
            .unwrap();
        let list = store.list().unwrap();
        assert_eq!(list[0].title, "My Research");
        assert!(!list[0].auto_title);
    }

    #[test]
    fn rename_delete_truncate() {
        let (store, _d) = temp_store();
        let s = store.create(None, None).unwrap();
        store.append(&s.id, &msg("1", "user", "a")).unwrap();
        store.append(&s.id, &msg("2", "assistant", "b")).unwrap();
        store.append(&s.id, &msg("3", "user", "c")).unwrap();

        store.truncate(&s.id, 1).unwrap();
        assert_eq!(store.get_messages(&s.id).unwrap().len(), 1);

        store.rename(&s.id, "Renamed".into()).unwrap();
        assert_eq!(store.list().unwrap()[0].title, "Renamed");

        store.delete(&s.id).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn corrupt_lines_skipped_on_read() {
        let (store, _d) = temp_store();
        let s = store.create(None, None).unwrap();
        store.append(&s.id, &msg("1", "user", "ok")).unwrap();
        let path = store.transcript_path(&uuid::Uuid::parse_str(&s.id).unwrap());
        fs::write(
            &path,
            format!("{}\nTHIS IS NOT JSON\n", fs::read_to_string(&path).unwrap()),
        )
        .unwrap();
        let msgs = store.get_messages(&s.id).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "ok");
    }

    #[test]
    fn compaction_marker_round_trips_through_the_transcript() {
        let (store, _d) = temp_store();
        let s = store.create(None, None).unwrap();
        store
            .append(&s.id, &msg("1", "user", "audit this repo"))
            .unwrap();
        let mut answer = msg("2", "assistant", "here is the analysis");
        answer.compaction = Some(CompactionMarker {
            summarized_messages: 1,
            summary: "earlier turn summarized".into(),
        });
        store.append(&s.id, &answer).unwrap();

        let messages = store.get_messages(&s.id).unwrap();
        assert_eq!(messages.len(), 2);
        let marker = messages[1]
            .compaction
            .as_ref()
            .expect("marker survives a reload");
        assert_eq!(marker.summarized_messages, 1);
        assert_eq!(marker.summary, "earlier turn summarized");
    }

    #[test]
    fn title_truncation() {
        let long = "x".repeat(100);
        let title = make_title(&long);
        assert!(title.chars().count() <= 61);
        assert!(title.ends_with('…'));
    }
}
