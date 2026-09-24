//! Scheduled re-scan state and due computation.
//!
//! The store is one SQLite file in app data; the due computation is pure so
//! the scheduler's decisions are testable without a clock. Stated limits
//! that shape the design: scans run only while the app is open (there is no
//! background service), one scheduled scan at a time, and a project whose
//! scan collides with a user scan simply waits for the next interval —
//! `last_started_at` moves when a scan actually starts, so a skipped tick
//! does not silently stretch the cadence.

use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

/// One project's re-scan schedule as stored.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleRecord {
    pub project_id: String,
    pub canonical_path: String,
    pub display_name: String,
    pub interval_hours: u32,
    pub enabled: bool,
    /// RFC 3339 timestamp of the last scan this schedule actually started.
    pub last_started_at: Option<String>,
}

pub const MIN_INTERVAL_HOURS: u32 = 1;
pub const MAX_INTERVAL_HOURS: u32 = 24 * 31;

/// Which schedules are due at `now`. Pure: the scheduler loop feeds it the
/// clock, tests feed it anything. A schedule is due when it is enabled and
/// either never started or its last start is at least one interval ago.
/// Timestamps that fail to parse count as never started — a corrupt stamp
/// errs toward scanning, the safe direction, not toward silence.
pub fn due(
    schedules: &[ScheduleRecord],
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<&ScheduleRecord> {
    schedules
        .iter()
        .filter(|schedule| {
            if !schedule.enabled {
                return false;
            }
            match schedule
                .last_started_at
                .as_deref()
                .and_then(|stamp| chrono::DateTime::parse_from_rfc3339(stamp).ok())
            {
                Some(last) => {
                    now - last.with_timezone(&chrono::Utc)
                        >= chrono::Duration::hours(schedule.interval_hours as i64)
                }
                None => true,
            }
        })
        .collect()
}

/// When a schedule next fires, if that is knowable.
pub fn next_due(record: &ScheduleRecord) -> Option<chrono::DateTime<chrono::Utc>> {
    if !record.enabled {
        return None;
    }
    let last = record
        .last_started_at
        .as_deref()
        .and_then(|stamp| chrono::DateTime::parse_from_rfc3339(stamp).ok())
        .map(|stamp| stamp.with_timezone(&chrono::Utc))?;
    Some(last + chrono::Duration::hours(record.interval_hours as i64))
}

#[derive(Debug)]
pub struct ScheduleStore {
    connection: Mutex<rusqlite::Connection>,
}

impl ScheduleStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create the schedule directory: {error}"))?;
        }
        let connection = rusqlite::Connection::open(path)
            .map_err(|error| format!("cannot open the schedule store: {error}"))?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scan_schedules (
                     project_id TEXT PRIMARY KEY,
                     canonical_path TEXT NOT NULL,
                     display_name TEXT NOT NULL,
                     interval_hours INTEGER NOT NULL,
                     enabled INTEGER NOT NULL,
                     last_started_at TEXT
                 )",
            )
            .map_err(|error| format!("cannot initialize the schedule store: {error}"))?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Upsert a schedule; the interval is clamped to the honest bounds a
    /// background-in-app scheduler can keep.
    pub fn upsert(
        &self,
        project_id: &str,
        canonical_path: &str,
        display_name: &str,
        interval_hours: u32,
        enabled: bool,
    ) -> Result<ScheduleRecord, String> {
        let interval_hours = interval_hours.clamp(MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS);
        let connection = self
            .connection
            .lock()
            .map_err(|_| "the schedule store is locked".to_owned())?;
        connection
            .execute(
                "INSERT INTO scan_schedules
                     (project_id, canonical_path, display_name, interval_hours, enabled, last_started_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)
                 ON CONFLICT(project_id) DO UPDATE SET
                     canonical_path = excluded.canonical_path,
                     display_name = excluded.display_name,
                     interval_hours = excluded.interval_hours,
                     enabled = excluded.enabled",
                rusqlite::params![
                    project_id,
                    canonical_path,
                    display_name,
                    interval_hours as i64,
                    i64::from(enabled),
                ],
            )
            .map_err(|error| format!("cannot save the schedule: {error}"))?;
        Ok(ScheduleRecord {
            project_id: project_id.to_owned(),
            canonical_path: canonical_path.to_owned(),
            display_name: display_name.to_owned(),
            interval_hours,
            enabled,
            last_started_at: None,
        })
    }

    pub fn list(&self) -> Vec<ScheduleRecord> {
        let Ok(connection) = self.connection.lock() else {
            return Vec::new();
        };
        let Ok(mut statement) = connection.prepare(
            "SELECT project_id, canonical_path, display_name, interval_hours,
                    enabled, last_started_at FROM scan_schedules
             ORDER BY display_name, project_id",
        ) else {
            return Vec::new();
        };
        statement
            .query_map([], |row| {
                Ok(ScheduleRecord {
                    project_id: row.get(0)?,
                    canonical_path: row.get(1)?,
                    display_name: row.get(2)?,
                    interval_hours: row
                        .get::<_, i64>(3)?
                        .clamp(1, i64::from(MAX_INTERVAL_HOURS))
                        as u32,
                    enabled: row.get::<_, i64>(4)? != 0,
                    last_started_at: row.get(5)?,
                })
            })
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// Record that a scan for this project actually started now.
    pub fn mark_started(&self, project_id: &str, now: &str) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "the schedule store is locked".to_owned())?;
        let changed = connection
            .execute(
                "UPDATE scan_schedules SET last_started_at = ?1 WHERE project_id = ?2",
                rusqlite::params![now, project_id],
            )
            .map_err(|error| format!("cannot update the schedule: {error}"))?;
        if changed == 0 {
            return Err(format!("no schedule for project {project_id}"));
        }
        Ok(())
    }

    pub fn remove(&self, project_id: &str) -> Result<(), String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "the schedule store is locked".to_owned())?;
        let changed = connection
            .execute(
                "DELETE FROM scan_schedules WHERE project_id = ?1",
                rusqlite::params![project_id],
            )
            .map_err(|error| format!("cannot remove the schedule: {error}"))?;
        if changed == 0 {
            return Err(format!("no schedule for project {project_id}"));
        }
        Ok(())
    }
}

/// The managed Tauri state, mirroring the rule-pack store's degradation: a
/// failed store means no scheduling, never a broken app.
pub struct ScheduleState {
    store: Option<ScheduleStore>,
    error: Option<String>,
}

impl ScheduleState {
    pub fn available(store: ScheduleStore) -> Self {
        Self {
            store: Some(store),
            error: None,
        }
    }

    pub fn unavailable(error: String) -> Self {
        Self {
            store: None,
            error: Some(error),
        }
    }

    pub fn store(&self) -> Result<&ScheduleStore, String> {
        self.store.as_ref().ok_or_else(|| {
            self.error
                .clone()
                .unwrap_or_else(|| "the schedule store is unavailable".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(
        project: &str,
        interval_hours: u32,
        enabled: bool,
        last: Option<&str>,
    ) -> ScheduleRecord {
        ScheduleRecord {
            project_id: project.into(),
            canonical_path: format!("/{project}"),
            display_name: project.into(),
            interval_hours,
            enabled,
            last_started_at: last.map(str::to_owned),
        }
    }

    #[test]
    fn never_started_enabled_schedules_are_due_immediately() {
        let schedules = vec![
            schedule("fresh", 24, true, None),
            schedule("disabled", 24, false, None),
        ];
        let now = chrono::Utc::now();
        let due = due(&schedules, now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].project_id, "fresh");
    }

    #[test]
    fn a_schedule_is_due_only_after_its_whole_interval() {
        let hour = chrono::Duration::hours(1);
        let base = chrono::Utc::now();
        let stamp = base.to_rfc3339();
        let schedules = vec![schedule("daily", 24, true, Some(&stamp))];
        assert!(due(&schedules, base + hour * 23).is_empty());
        assert_eq!(due(&schedules, base + hour * 24).len(), 1);
        // A corrupt stamp reads as never started: scan, don't stay silent.
        let corrupt = vec![schedule("corrupt", 24, true, Some("yesterday-ish"))];
        assert_eq!(due(&corrupt, base).len(), 1);
    }

    #[test]
    fn next_due_is_computable_only_for_enabled_started_schedules() {
        assert!(next_due(&schedule("a", 24, false, Some("2026-09-24T00:00:00Z"))).is_none());
        assert!(next_due(&schedule("a", 24, true, None)).is_none());
        let next = next_due(&schedule("a", 24, true, Some("2026-09-24T00:00:00Z"))).unwrap();
        assert_eq!(next.to_rfc3339(), "2026-09-25T00:00:00+00:00");
    }

    #[test]
    fn the_store_round_trips_and_marks_real_starts() {
        let directory = tempfile::tempdir().unwrap();
        let store = ScheduleStore::open(&directory.path().join("schedules.sqlite3")).unwrap();

        let record = store
            .upsert("p1", "/tmp/project", "Project", 24, true)
            .unwrap();
        assert_eq!(record.interval_hours, 24);
        // Clamped to the bounds the in-app scheduler can keep.
        assert_eq!(
            store
                .upsert("p2", "/tmp/x", "X", 0, true)
                .unwrap()
                .interval_hours,
            MIN_INTERVAL_HOURS
        );
        assert_eq!(
            store
                .upsert("p3", "/tmp/y", "Y", 100_000, true)
                .unwrap()
                .interval_hours,
            MAX_INTERVAL_HOURS
        );

        assert_eq!(store.list().len(), 3);
        store.mark_started("p1", "2026-09-24T00:00:00Z").unwrap();
        assert_eq!(
            store.list()[0].last_started_at.as_deref(),
            Some("2026-09-24T00:00:00Z")
        );
        // Updating a schedule keeps the recorded start, so re-tuning an
        // interval does not instantly re-fire every project.
        store
            .upsert("p1", "/tmp/project", "Project", 12, true)
            .unwrap();
        assert_eq!(
            store.list()[0].last_started_at.as_deref(),
            Some("2026-09-24T00:00:00Z")
        );

        store.remove("p1").unwrap();
        assert!(store.remove("p1").is_err());
        assert_eq!(store.list().len(), 2);
    }
}
