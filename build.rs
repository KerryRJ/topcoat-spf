// Cargo sets `CARGO_PRIMARY_PACKAGE` while compiling the package, not while
// running its build script, so capture it at build-script compile time.
const PRIMARY_PACKAGE: bool = option_env!("CARGO_PRIMARY_PACKAGE").is_some();

fn main() {
    if std::env::var_os("CARGO_FEATURE_UI").is_some() {
        topcoat::icon::iconify::BuildConfig::new()
            .icon_set("lucide")
            .stage()
            .expect("stage Lucide icons");
    }

    // Tailwind output is needed by the preview binary and example, which are
    // only built from this package. Skip it when a host builds the crate as a
    // dependency, even though the preview feature is now on by default.
    if std::env::var_os("CARGO_FEATURE_PREVIEW").is_some() && PRIMARY_PACKAGE {
        // `styles.css` scans these paths for utility classes.
        println!("cargo:rerun-if-changed=styles.css");
        println!("cargo:rerun-if-changed=src");
        println!("cargo:rerun-if-changed=examples");
        topcoat::tailwind::BuildConfig::new()
            .input("styles.css")
            .render()
            .expect("render Tailwind CSS for the browser preview");
    }
}
