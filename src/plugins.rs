//! Runtime extensions for providers, accounts, and application-specific hosts.
//!
//! The registry keeps typed extension values rather than modifying the host's vtable.
//! Use an `Arc<Provider>` or `Arc<Account>` as the host when an extension needs to retain it.
//! Installation failures leave the registry unchanged. Each concrete plugin type occupies
//! one slot; different configuration of the same plugin must be removed before replacement.
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    error::Error,
    fmt,
};

/// A plugin which constructs a typed extension for a host.
pub trait Plugin<H>: Send + Sync + 'static {
    /// API value exposed after installation.
    type Extension: Send + Sync + 'static;
    /// Initialization error; no registry changes are committed on failure.
    type Error: Error + Send + Sync + 'static;
    /// A stable, nonempty name, unique within a host.
    fn name(&self) -> &'static str;
    /// Creates the extension. External side effects are the plugin's responsibility.
    fn install(&self, host: &H) -> Result<Self::Extension, Self::Error>;
}

struct Entry {
    name: &'static str,
    extension: Box<dyn Any + Send + Sync>,
}

/// A host together with independently installable, type-safe runtime extensions.
pub struct PluginHost<H> {
    host: H,
    entries: HashMap<TypeId, Entry>,
}
impl<H: fmt::Debug> fmt::Debug for PluginHost<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginHost")
            .field("host", &self.host)
            .field("plugins", &self.names())
            .finish()
    }
}

/// Failure to install an extension.
#[derive(Debug)]
pub enum InstallError<E> {
    /// The plugin type or name is already installed.
    Duplicate(&'static str),
    /// Plugin names must not be empty or whitespace.
    InvalidName,
    /// Plugin initialization failed without modifying the registry.
    Initialization(E),
}
impl<E: fmt::Display> fmt::Display for InstallError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(f, "plugin {name} is already installed"),
            Self::InvalidName => f.write_str("plugin name is empty"),
            Self::Initialization(error) => write!(f, "plugin initialization failed: {error}"),
        }
    }
}
impl<E: Error + 'static> Error for InstallError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Initialization(error) => Some(error),
            _ => None,
        }
    }
}
impl<H> PluginHost<H> {
    /// Wraps a host. The host remains accessible through [`Self::host`].
    pub fn new(host: H) -> Self {
        Self {
            host,
            entries: HashMap::new(),
        }
    }
    /// Gets the original host without erasing its provider/account type.
    pub const fn host(&self) -> &H {
        &self.host
    }
    /// Consumes the wrapper and drops all installed extension values.
    pub fn into_host(self) -> H {
        self.host
    }
    /// Installs a plugin once and returns its typed API.
    pub fn install<P: Plugin<H>>(
        &mut self,
        plugin: P,
    ) -> Result<&P::Extension, InstallError<P::Error>> {
        let id = TypeId::of::<P>();
        let name = plugin.name();
        if name.trim().is_empty() {
            return Err(InstallError::InvalidName);
        }
        if self.entries.contains_key(&id) || self.entries.values().any(|entry| entry.name == name) {
            return Err(InstallError::Duplicate(name));
        }
        let extension = plugin
            .install(&self.host)
            .map_err(InstallError::Initialization)?;
        self.entries.insert(
            id,
            Entry {
                name,
                extension: Box::new(extension),
            },
        );
        Ok(self
            .get::<P>()
            .expect("installed extension has its declared type"))
    }
    /// Looks up an installed plugin by its concrete type.
    pub fn get<P: Plugin<H>>(&self) -> Option<&P::Extension> {
        self.entries
            .get(&TypeId::of::<P>())?
            .extension
            .downcast_ref()
    }
    /// Gets mutable access to an extension without allowing its type to change.
    pub fn get_mut<P: Plugin<H>>(&mut self) -> Option<&mut P::Extension> {
        self.entries
            .get_mut(&TypeId::of::<P>())?
            .extension
            .downcast_mut()
    }
    /// Removes a plugin, returning ownership of its extension.
    pub fn remove<P: Plugin<H>>(&mut self) -> Option<P::Extension> {
        self.entries
            .remove(&TypeId::of::<P>())?
            .extension
            .downcast::<P::Extension>()
            .ok()
            .map(|entry| *entry)
    }
    /// Returns installed names in deterministic alphabetical order.
    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self.entries.values().map(|entry| entry.name).collect();
        names.sort_unstable();
        names
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct SetupError;
    impl fmt::Display for SetupError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("setup")
        }
    }
    impl Error for SetupError {}
    struct Counter {
        name: &'static str,
        fail: bool,
    }
    impl Plugin<usize> for Counter {
        type Extension = usize;
        type Error = SetupError;
        fn name(&self) -> &'static str {
            self.name
        }
        fn install(&self, host: &usize) -> Result<usize, SetupError> {
            if self.fail {
                Err(SetupError)
            } else {
                Ok(*host)
            }
        }
    }
    #[test]
    fn installation_lookup_removal_and_rollback() {
        let mut host = PluginHost::new(42);
        assert!(matches!(
            host.install(Counter {
                name: "counter",
                fail: true
            }),
            Err(InstallError::Initialization(_))
        ));
        assert!(host.names().is_empty());
        assert!(matches!(
            host.install(Counter {
                name: " ",
                fail: false
            }),
            Err(InstallError::InvalidName)
        ));
        assert_eq!(
            *host
                .install(Counter {
                    name: "counter",
                    fail: false
                })
                .unwrap(),
            42
        );
        assert!(matches!(
            host.install(Counter {
                name: "other",
                fail: false
            }),
            Err(InstallError::Duplicate(_))
        ));
        *host.get_mut::<Counter>().unwrap() += 1;
        assert_eq!(host.remove::<Counter>(), Some(43));
        assert!(host.get::<Counter>().is_none());
        assert_eq!(host.into_host(), 42);
    }
    struct SameName;
    impl Plugin<usize> for SameName {
        type Extension = String;
        type Error = SetupError;
        fn name(&self) -> &'static str {
            "counter"
        }
        fn install(&self, _: &usize) -> Result<String, SetupError> {
            Ok("different".into())
        }
    }
    #[test]
    fn duplicate_names_are_rejected_across_plugin_types() {
        let mut host = PluginHost::new(0);
        host.install(Counter {
            name: "counter",
            fail: false,
        })
        .unwrap();
        assert!(matches!(
            host.install(SameName),
            Err(InstallError::Duplicate("counter"))
        ));
        assert_eq!(host.names(), ["counter"]);
    }
}
