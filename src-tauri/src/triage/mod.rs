//! Turning scanner hits into findings that survived an attempt to disprove them.
//!
//! oxAudit's source scanner is fifty regular expressions, and every hit is
//! currently presented as a result. That is the tool
//! [VulnHunter](https://github.com/capitalone/VulnHunter) (Apache-2.0) was
//! written as a reaction against, and its method is worth adopting: treat every
//! hit as a *candidate*, and make something try to eliminate it.
//!
//! Three pieces are built here, and each is an invariant rather than a
//! convention — the point of moving this out of a prompt and into code is that
//! a prompt cannot enforce anything:
//!
//! - [`gates`] — the five falsification questions, and the rules about what a
//!   verdict has to establish before it is allowed to claim a conclusion.
//! - [`manifest`] — the guard that makes a finding impossible to drop silently
//!   between scanning and reporting.
//! - [`scope`] — where a finding is worth reporting from, keeping
//!   security-relevant configuration in scope where a plain ignore-list would
//!   discard it.
//!
//! Nothing is copied from VulnHunter: it is a set of Claude Code skills —
//! markdown prompts — so what transfers is the argument, not an implementation.

pub mod gates;
pub mod manifest;
pub mod scope;
