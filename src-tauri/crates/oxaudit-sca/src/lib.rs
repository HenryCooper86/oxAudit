//! Software composition analysis rules, independent of storage, transport
//! and presentation: license classification, the component policy, release
//! facts, the composition report, the portfolio view and the notices file.
//!
//! Everything here is a pure function of its inputs. Reading policy files,
//! fetching release facts and loading stored runs belong to the host crate.

pub mod license;
pub mod notices;
pub mod policy;
pub mod portfolio;
pub mod release;
pub mod report;

pub use license::{LicenseAssessment, LicenseCategory};
pub use policy::{Action, ComponentPolicy, Violation, ViolationKind};
pub use release::ReleaseInfo;
pub use report::{ComponentAdvisory, ComponentInput, ScaComponent, ScaReport};
