//! Release facts about one installed package version, as a registry index
//! reported them. Every field is optional: a fact the index did not state is
//! unknown, and a rule over an unknown fact does not fire.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseInfo {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// When the installed version was published (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    /// The version the registry serves by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    /// When the newest release of the package was published (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_published_at: Option<String>,
    /// Releases that order above the installed one. Unknown when the
    /// ecosystem's versions could not be compared with certainty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newer_versions: Option<u32>,
    /// Major versions between the installed and the default version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub major_versions_behind: Option<u32>,
    /// The registry marks the installed version deprecated (npm deprecation,
    /// a yanked crate, a NuGet deprecation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated_reason: Option<String>,
}

fn days_since(stamp: Option<&str>, now: DateTime<Utc>) -> Option<u32> {
    let published = DateTime::parse_from_rfc3339(stamp?)
        .ok()?
        .with_timezone(&Utc);
    // A publication time in the future is a clock or data fault, not age 0.
    u32::try_from((now - published).num_days()).ok()
}

impl ReleaseInfo {
    /// Whole days since the installed version was published.
    pub fn age_days(&self, now: DateTime<Utc>) -> Option<u32> {
        days_since(self.published_at.as_deref(), now)
    }

    /// Whole days since the package last published any release.
    pub fn days_since_latest_release(&self, now: DateTime<Utc>) -> Option<u32> {
        days_since(self.latest_published_at.as_deref(), now)
    }

    /// Whether the index stated anything at all about this version.
    pub fn has_facts(&self) -> bool {
        self.published_at.is_some()
            || self.latest_version.is_some()
            || self.latest_published_at.is_some()
            || self.deprecated.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_are_whole_days_and_unknown_when_unstated_or_in_the_future() {
        let now: DateTime<Utc> = "2026-11-16T12:00:00Z".parse().unwrap();
        let release = ReleaseInfo {
            published_at: Some("2025-11-16T12:00:00Z".into()),
            latest_published_at: Some("2026-11-15T11:00:00+00:00".into()),
            ..Default::default()
        };
        assert_eq!(release.age_days(now), Some(365));
        assert_eq!(release.days_since_latest_release(now), Some(1));
        assert!(release.has_facts());

        let unknown = ReleaseInfo::default();
        assert_eq!(unknown.age_days(now), None);
        assert!(!unknown.has_facts());

        let future = ReleaseInfo {
            published_at: Some("2027-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        assert_eq!(future.age_days(now), None);
        let garbled = ReleaseInfo {
            published_at: Some("last tuesday".into()),
            ..Default::default()
        };
        assert_eq!(garbled.age_days(now), None);
    }
}
