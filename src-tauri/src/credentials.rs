use std::fmt;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::findings::error::CommandError;
use crate::models::{AiSettings, CredentialMutation};

#[cfg_attr(test, allow(dead_code))]
const SERVICE: &str = "com.oxaudit.desktop";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    AiProvider,
    Nvd,
}

impl CredentialKind {
    #[cfg_attr(test, allow(dead_code))]
    fn account(self) -> &'static str {
        match self {
            Self::AiProvider => "ai-provider-api-key",
            Self::Nvd => "nvd-api-key",
        }
    }
}

pub trait CredentialStore: Send + Sync {
    fn get(&self, kind: CredentialKind) -> Result<Option<Zeroizing<String>>, CommandError>;
    fn set(&self, kind: CredentialKind, value: &str) -> Result<(), CommandError>;
    fn delete(&self, kind: CredentialKind) -> Result<(), CommandError>;
}

pub struct ResolvedAiSettings {
    pub config: AiSettings,
    pub api_key: Option<Zeroizing<String>>,
}

impl std::ops::Deref for ResolvedAiSettings {
    type Target = AiSettings;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

pub fn resolve_ai_settings(
    settings: &AiSettings,
    store: &dyn CredentialStore,
    mutation: Option<&CredentialMutation>,
) -> Result<ResolvedAiSettings, CommandError> {
    let api_key = match mutation.unwrap_or(&CredentialMutation::Unchanged) {
        CredentialMutation::Unchanged => store.get(CredentialKind::AiProvider)?,
        CredentialMutation::Replace { value } => {
            let value = value.trim();
            (!value.is_empty()).then(|| Zeroizing::new(value.to_owned()))
        }
        CredentialMutation::Delete => None,
    };
    Ok(ResolvedAiSettings {
        config: settings.clone(),
        api_key,
    })
}

pub fn resolve_nvd_key(
    store: &dyn CredentialStore,
) -> Result<Option<Zeroizing<String>>, CommandError> {
    store.get(CredentialKind::Nvd)
}

#[derive(Default)]
#[cfg_attr(test, allow(dead_code))]
pub struct KeyringCredentialStore;

impl fmt::Debug for KeyringCredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyringCredentialStore")
            .field("service", &SERVICE)
            .finish_non_exhaustive()
    }
}

impl KeyringCredentialStore {
    #[cfg_attr(test, allow(dead_code))]
    fn entry(kind: CredentialKind) -> Result<keyring::Entry, CommandError> {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows",
            target_os = "linux"
        ))]
        {
            keyring::Entry::new(SERVICE, kind.account())
                .map_err(|_| CommandError::credential_unavailable())
        }

        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows",
            target_os = "linux"
        )))]
        {
            let _ = kind;
            Err(CommandError::credential_unavailable())
        }
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn get(&self, kind: CredentialKind) -> Result<Option<Zeroizing<String>>, CommandError> {
        match Self::entry(kind)?.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(CommandError::credential_unavailable()),
        }
    }

    fn set(&self, kind: CredentialKind, value: &str) -> Result<(), CommandError> {
        if value.trim().is_empty() {
            return self.delete(kind);
        }
        Self::entry(kind)?
            .set_password(value)
            .map_err(|_| CommandError::credential_unavailable())
    }

    fn delete(&self, kind: CredentialKind) -> Result<(), CommandError> {
        match Self::entry(kind)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(CommandError::credential_unavailable()),
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryCredentialStore {
    values: Mutex<HashMap<CredentialKind, Zeroizing<String>>>,
}

#[cfg(test)]
impl fmt::Debug for MemoryCredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stored = self.values.lock().map(|values| values.len()).unwrap_or(0);
        formatter
            .debug_struct("MemoryCredentialStore")
            .field("stored_credentials", &stored)
            .finish()
    }
}

#[cfg(test)]
impl CredentialStore for MemoryCredentialStore {
    fn get(&self, kind: CredentialKind) -> Result<Option<Zeroizing<String>>, CommandError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| CommandError::credential_unavailable())?
            .get(&kind)
            .map(|value| Zeroizing::new(value.to_string())))
    }

    fn set(&self, kind: CredentialKind, value: &str) -> Result<(), CommandError> {
        if value.trim().is_empty() {
            return self.delete(kind);
        }
        self.values
            .lock()
            .map_err(|_| CommandError::credential_unavailable())?
            .insert(kind, Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn delete(&self, kind: CredentialKind) -> Result<(), CommandError> {
        self.values
            .lock()
            .map_err(|_| CommandError::credential_unavailable())?
            .remove(&kind);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_sets_reads_and_deletes_without_debug_disclosure() {
        let store = MemoryCredentialStore::default();
        store
            .set(CredentialKind::AiProvider, "canary-key")
            .expect("set");
        assert_eq!(
            store
                .get(CredentialKind::AiProvider)
                .expect("get")
                .as_deref()
                .map(String::as_str),
            Some("canary-key")
        );
        assert!(!format!("{store:?}").contains("canary-key"));

        store.delete(CredentialKind::AiProvider).expect("delete");
        assert!(store
            .get(CredentialKind::AiProvider)
            .expect("get")
            .is_none());
    }

    #[test]
    fn blank_values_delete_instead_of_creating_ambiguous_entries() {
        let store = MemoryCredentialStore::default();
        store.set(CredentialKind::Nvd, "key").expect("set");
        store.set(CredentialKind::Nvd, "  ").expect("delete");
        assert!(store.get(CredentialKind::Nvd).expect("get").is_none());
    }
}
