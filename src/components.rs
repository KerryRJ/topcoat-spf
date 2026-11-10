//! Installed Topcoat UI components used by the reusable SPF panel.
//!
//! These files are genuine `topcoat ui` installs copied without modification
//! from the application's existing component install. Keep `components.toml`
//! in sync with `topcoat ui`; do not edit the installed files for
//! application-specific behaviour.

#[path = "components/alert.rs"]
pub mod alert;
#[path = "components/button.rs"]
pub mod button;
#[path = "components/spinner.rs"]
pub mod spinner;
#[path = "components/switch.rs"]
pub mod switch;
