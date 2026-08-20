//! Session persistence: JSONL transcript per session + a `sessions.json`
//! index. Modeled on y-agent's `transcript.rs` (append-only, corrupt lines
//! skipped on read) with a lightweight metadata index instead of SQLite.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

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
    pub at: String,
}

pub struct SessionStore {
    pub dir: PathBuf,
}

impl SessionStore {
    pub fn new(app: &tauri::AppHandle) -> Result<Self, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("cannot resolve config dir: {e}"))?
            .join("sessions");
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create sessions dir: {e}"))?;
        Ok(Self { dir })
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("sessions.json")
    }

    fn transcript_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.jsonl"))
    }

    fn load_index(&self) -> Result<Vec<SessionInfo>, String> {
        match fs::read_to_string(self.index_path()) {
            Ok(content) => serde_json::from_str(&content).map_err(|e| e.to_string()),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn save_index(&self, index: &[SessionInfo]) -> Result<(), String> {
        let content = serde_json::to_string_pretty(index).map_err(|e| e.to_string())?;
        fs::write(self.index_path(), content).map_err(|e| format!("cannot write index: {e}"))
    }

    fn now() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    // ------------------------------------------------------------------ list
    pub fn list(&self) -> Result<Vec<SessionInfo>, String> {
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
        let auto_title = title.is_none();
        let info = SessionInfo {
            id: uuid::Uuid::new_v4().to_string(),
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
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.transcript_path(&info.id))
            .map_err(|e| format!("cannot create transcript: {e}"))?;
        Ok(info)
    }

    // ------------------------------------------------------------ get_messages
    pub fn get_messages(&self, id: &str) -> Result<Vec<StoredMessage>, String> {
        let content = match fs::read_to_string(self.transcript_path(id)) {
            Ok(c) => c,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for line in content.lines() {
            if let Ok(msg) = serde_json::from_str::<StoredMessage>(line) {
                out.push(msg);
            }
            // corrupt lines are skipped — crash mid-append never breaks the read
        }
        Ok(out)
    }

    // ----------------------------------------------------------------- append
    /// Append one message; updates metadata and auto-titles the session from
    /// its first user message. Returns the updated `SessionInfo`.
    pub fn append(&self, id: &str, msg: &StoredMessage) -> Result<SessionInfo, String> {
        let mut index = self.load_index()?;
        let pos = index
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| format!("session not found: {id}"))?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.transcript_path(id))
            .map_err(|e| format!("cannot open transcript: {e}"))?;
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
        let title = title.trim().to_string();
        if title.is_empty() {
            return Err("title cannot be empty".into());
        }
        let mut index = self.load_index()?;
        let info = index
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| format!("session not found: {id}"))?;
        info.title = title;
        info.auto_title = false;
        self.save_index(&index)
    }

    // ----------------------------------------------------------------- delete
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut index = self.load_index()?;
        let before = index.len();
        index.retain(|s| s.id != id);
        if index.len() == before {
            return Err(format!("session not found: {id}"));
        }
        self.save_index(&index)?;
        let _ = fs::remove_file(self.transcript_path(id));
        Ok(())
    }

    // --------------------------------------------------------------- truncate
    /// Keep only the first `keep` messages (rewind / clear).
    pub fn truncate(&self, id: &str, keep: usize) -> Result<(), String> {
        let messages = self.get_messages(id)?;
        let kept: Vec<&StoredMessage> = messages.iter().take(keep).collect();
        let kept_len = kept.len();
        let path = self.transcript_path(id);
        if kept.is_empty() {
            fs::write(&path, "").map_err(|e| format!("cannot truncate: {e}"))?;
        } else {
            let mut content = String::new();
            for m in &kept {
                content.push_str(&serde_json::to_string(m).map_err(|e| e.to_string())?);
                content.push('\n');
            }
            fs::write(&path, content).map_err(|e| format!("cannot truncate: {e}"))?;
        }
        let mut index = self.load_index()?;
        let info = index
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| format!("session not found: {id}"))?;
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
            at: "2026-01-01T00:00:00Z".into(),
        }
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
        let path = store.transcript_path(&s.id);
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
    fn title_truncation() {
        let long = "x".repeat(100);
        let title = make_title(&long);
        assert!(title.chars().count() <= 61);
        assert!(title.ends_with('…'));
    }
}
