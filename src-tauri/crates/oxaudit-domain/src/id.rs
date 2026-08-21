use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DomainError;

macro_rules! domain_id {
    ($name:ident, $kind:literal, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(format!("{}_{}", $prefix, uuid::Uuid::new_v4()))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(DomainError::EmptyId { kind: $kind });
                }
                if value.len() > 200 {
                    return Err(DomainError::IdTooLong { kind: $kind });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

domain_id!(RunId, "run", "run");
domain_id!(ArtifactId, "artifact", "artifact");
domain_id!(ComponentId, "component", "component");
domain_id!(ObservationId, "observation", "observation");
domain_id!(EvidenceId, "evidence", "evidence");
domain_id!(FindingId, "finding", "finding");
domain_id!(RulePackId, "rule pack", "rulepack");
domain_id!(ProviderSnapshotId, "provider snapshot", "provider");
domain_id!(VerificationId, "verification", "verification");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_serialization_is_a_stable_string() {
        let id = RunId::parse("run_fixture-1").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"run_fixture-1\"");
        assert_eq!(
            serde_json::from_str::<RunId>("\"run_fixture-1\"").unwrap(),
            id
        );
    }

    #[test]
    fn invalid_deserialized_identity_is_rejected() {
        assert!(serde_json::from_str::<FindingId>("\"  \"").is_err());
    }
}
