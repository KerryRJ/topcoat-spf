# topcoat-spf

Reusable, asynchronous SPF inspection and rewriting with an optional Topcoat UI.
The crate owns SPF parsing, conservative rewriting, provider read-back
verification and the panel. The host owns authentication, authorization,
DNS/provider configuration, public-address discovery and persistence. The crate
ships no concrete DNS provider or public-address discovery adapter.

```toml
[dependencies]
topcoat-spf = { path = "../topcoat-spf" }
```

## Feature flags

| Feature | Default | Enables |
| --- | --- | --- |
| `ui` | yes | The reusable `ui::spf_panel` Topcoat component and its installed component modules. |
| `preview` | yes | The `preview` binary and `examples/preview.rs`, a runnable browser preview with fixture DNS and address state and no external services (implies `ui`). |

`preview` is enabled by default so a plain `topcoat dev` can build the preview
binary; the CLI invokes `cargo build` without feature flags. Disable defaults
for a core-only build:

```toml
topcoat-spf = { path = "../topcoat-spf", default-features = false }
```

The core crate always provides the SPF parser/rewriter, the service traits and
`inspect`/`apply`. It bundles no DNS provider or public-address discovery
adapter: hosts implement `SpfDns` and `PublicAddressDiscovery` in their own
crate and inject those values into the service.

SPF parsing uses `mail-auth` 0.15. This crate enables its pure-Rust crypto and
Hickory backends so it builds without a native crypto toolchain. Cargo feature
unification lets a host that enables `aws-lc-rs` use that backend instead;
`mail-auth` gates its pure-Rust implementations out when `aws-lc-rs` is on.

## Browser preview

`examples/preview/app.rs` renders the panel from an in-memory fixture DNS
source, fixture last-applied addresses and fixture public IPv4/IPv6 addresses.
All values use documentation ranges, and the shared preview module supplies the
addresses through a local `PublicAddressDiscovery` implementation, so no page
load, Refresh or Publish contacts a provider or public-address service. Each
page load and Refresh builds the Proposed record and status through the normal
`inspect` service and rewrite rules, bounded by a 10-second overall inspection
timeout. Inspection is skipped when either setting is disabled. The public
address fields show the fixture addresses; a missing family would be reported,
and the proposal would remove the fixture's previously applied directive for
that family. A timeout or inspection failure leaves Proposed blank with an
error instead of presenting fixture data as a result.

The default enabled page returns its header, theme control, provider simulation
and an accessible loading status immediately. It then fetches
`/panel?enabled=…&provider=…` and replaces the loading region with the rendered
panel when the fixture inspection finishes. The loader uses an animated spinner
with a `role="status"` announcement and the visible text "Preparing the SPF
panel…". Inspection errors and timeouts remain visible in the inserted panel.
Disabled settings render the panel immediately during the page request and skip
inspection. If JavaScript is unavailable, or the fragment request fails,
a fallback link (and `?full=1`) renders the panel during the page request; the
full-page forms preserve `full`, `enabled` and `provider` so switching and
refreshing keep working without JavaScript.

Its Refresh control reloads the page and repeats the fixture inspection through
the same loading shell, its Publish control POSTs to `/apply`, and its Enable
switch POSTs to `/enable`; all handlers only redirect back without writing DNS,
provider credentials or records. Publish is simulated and never calls `apply`. Starting
either action immediately shows its spinner and a visible, announced
Refreshing… or Publishing… label, and repeat action submissions are ignored
until the navigation completes. A preview-only switch POSTs to `/provider` to
simulate the saved DNS provider setting: turning it off disables the SPF switch,
Refresh and Publish, and turning it back on restores the independent SPF setting
remembered in the query string. The SPF switch starts on and `?enabled=0` turns
the independent SPF setting off. `?provider=0` also disables the provider.
The panel renders directly on the page background without an enclosing card.
The header's icon-only theme control starts in dark mode and remembers a light
or dark choice in browser storage.
The same module backs the `preview` binary (`src/bin/preview.rs`) and
`examples/preview.rs`.

Start the Topcoat development server from the project root:

```sh
topcoat dev
```

`topcoat dev` builds the `preview` binary with the package's default features,
serves it, and rebuilds it when the preview source changes. Open
<http://127.0.0.1:3000/>. Override the bind address with `HOST` and `PORT` if
needed:

```sh
HOST=0.0.0.0 PORT=8080 topcoat dev
```

The example remains available and runs the same app:

```sh
cargo run --example preview --features preview
```

`cargo run --bin preview` starts the same server without the watcher.

The first preview build downloads the pinned standalone Tailwind CLI and
renders `styles.css`. `build.rs` only does this when `preview` is enabled and
this crate is the primary package, so `topcoat dev`, the binary and the
example trigger it while a host that builds `topcoat-spf` as a dependency does
not. `styles.css` is a copy of the Topcoat UI neutral theme and scans `src` and
`examples` for classes. The preview serves the generated CSS inline, so it does
not require a separate `topcoat asset bundle` step.

## What it does

* Detects `v=spf1` TXT values case-insensitively.
* Replaces or removes only exact `pass` `ip4`/`ip6` host directives that match
  the previously published addresses.
* Preserves unrelated SPF mechanisms, modifiers and their original spelling and
  order, including `redirect=`, `include:`, CIDR mechanisms, qualified
  mechanisms and `-all`/`~all`.
* Preserves every unrelated TXT value in the RRset.
* Creates a missing record as `v=spf1 <addresses> ~all`.
* Rejects multiple SPF records and invalid records before writing.
* Refuses private, loopback, link-local, unspecified and multicast addresses.
  An unusable discovered family is treated as unavailable: its previously
  applied host directive is removed and the family is cleared from the saved
  addresses. When neither family is available, `apply` stops with
  `NoDiscoveredAddress` without reading or writing DNS and without changing
  saved addresses.
* Reads the provider back after writing and verifies the complete TXT set.
* Is idempotent: an already-desired RRset produces no DNS write.

The desired SPF value is appended after unrelated TXT values, matching the
previous application behaviour.

## Core traits

The service is composed from four narrow capabilities. Their futures are
`Send`, so the service can run on multithreaded async servers. A host may
implement `SpfDns` over a provider API, authoritative DNS, or a deterministic
test double; the `InspectRequest::source` label documents which source the
snapshot came from.

```rust
use std::future::Future;
use topcoat_spf::{SpfAddresses, Availability, DiscoveredAddresses};

pub trait SpfDns: Send + Sync {
    type Error: std::fmt::Display + Send + Sync + 'static;
    fn txt_records(&self, name: &str)
        -> impl Future<Output = Result<Vec<String>, Self::Error>> + Send;
    fn replace_txt_records(&self, name: &str, records: &[String])
        -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait SpfAddressStore: Send + Sync {
    type Error: std::fmt::Display + Send + Sync + 'static;
    fn load(&self, domain: &str)
        -> impl Future<Output = Result<SpfAddresses, Self::Error>> + Send;
    fn save(&self, domain: &str, addresses: &SpfAddresses)
        -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait WritePolicy: Send + Sync {
    type Error: std::fmt::Display + Send + Sync + 'static;
    fn check(&self)
        -> impl Future<Output = Result<Availability, Self::Error>> + Send;
}

pub trait PublicAddressDiscovery: Send + Sync {
    type Error: std::fmt::Display + Send + Sync + 'static;
    fn discover(&self)
        -> impl Future<Output = Result<DiscoveredAddresses, Self::Error>> + Send;
}
```

Implementations can use `async fn`. `MemorySpfAddressStore` and
`FixedWritePolicy` are provided for examples, previews and tests. The crate
ships no concrete `SpfDns` or `PublicAddressDiscovery`; hosts own those adapters
and pass them to `inspect` and `apply`.

`SpfAddressStore` holds only the latest successfully published IPv4/IPv6
addresses per domain. A family that discovery did not provide is cleared after
a verified update rather than retained from the previous value. It is not a
record of discovered addresses and not a history of past values. `apply` saves
only after the provider read-back verifies the complete expected TXT set; a
failed discovery, lookup, write or verification leaves the stored values
unchanged. Use `SpfAddresses::replaced_with` to build the next value; the old
`merged_with` name remains as a deprecated alias with the same behaviour.

## Inspect and apply

```rust,no_run
use topcoat_spf::{InspectRequest, SpfError, apply, inspect};

async fn example<D, A, S, P>(
    dns: &D,
    discovery: &A,
    store: &S,
    policy: &P,
) -> Result<(), SpfError>
where
    D: topcoat_spf::SpfDns,
    A: topcoat_spf::PublicAddressDiscovery,
    S: topcoat_spf::SpfAddressStore,
    P: topcoat_spf::WritePolicy,
{
    let snapshot = inspect(
        dns,
        discovery,
        store,
        policy,
        &InspectRequest::new("example.com", "Cloudflare"),
    )
    .await;

    let result = apply(dns, store, discovery, policy, "example.com").await?;
    Ok(())
}
```

`inspect` is resilient: DNS, discovery, storage and policy failures are
collected into `Snapshot::error`, while known values still render. Both
`inspect` and `apply` trim surrounding whitespace from the domain; hosts must
still validate it. `apply` returns a typed `SpfError` and performs this
sequence:

1. Check the settings-backed `WritePolicy`.
2. Discover public addresses. If neither family is available, stop before DNS.
   A missing family is not carried over; its previously managed directive is
   removed and the saved family is cleared after verification.
3. Load the last successfully published addresses.
4. Read the TXT RRset.
5. Rewrite the SPF value, preserving unrelated TXT values.
6. Re-check `WritePolicy` immediately before a write.
7. Replace the TXT RRset if it changed.
8. Read it back and verify the complete expected set.
9. Save the newly published addresses.

After a successful `apply`, call `inspect` again if the host wants a refreshed
snapshot that includes a new source read and a fresh discovery result. The
service does not perform a second discovery or a host-specific authoritative
DNS check after saving.

## Settings-backed policy

Implement `WritePolicy` over the host's saved SPF and provider settings and
return only non-secret availability. The service checks it at the start of
`apply` and again before any DNS write.

```rust,ignore
impl WritePolicy for HostSettingsStore {
    type Error = HostError;

    async fn check(&self) -> Result<Availability, Self::Error> {
        let settings = self.load_spf_settings().await?;
        let Some(provider) = settings.dns_provider else {
            return Ok(Availability::disabled(
                "Configure a DNS provider in DNS settings before applying SPF changes.",
            ));
        };
        Ok(Availability {
            // The panel's Enable switch reads and writes only this SPF setting.
            spf_enabled: settings.spf_enabled,
            // The host maintains the provider flag in DNS settings separately.
            provider_enabled: provider.enabled,
            write_available: provider.credentials_present && !settings.maintenance_mode,
            reason: (!provider.enabled)
                .then(|| "Enable the DNS provider in DNS settings before applying SPF changes.".into())
                .or_else(|| {
                    (!settings.spf_enabled)
                        .then(|| "Enable SPF before applying changes.".into())
                }),
        })
    }
}
```

`Availability.spf_enabled` mirrors the host's saved SPF enabled setting and is
the only state controlled by the panel's Enable switch.
`Availability.provider_enabled` mirrors the provider's saved enabled flag and is
independent of it. `Availability.write_available` can add host policy such as
missing credentials or maintenance mode. Refresh requires both enabled settings;
writes require both settings and `write_available`. `FixedWritePolicy` is
available when a host has already performed an explicit guard and wants a fixed
snapshot, but a settings-backed policy is safer for long-lived servers.

A re-check narrows the race between disabling SPF or the provider and a pending
write; it is not a distributed lock. A settings change after the final check can
still race with the provider request.

## Host-owned adapters

The crate defines `SpfDns`, `SpfAddressStore`, `WritePolicy` and
`PublicAddressDiscovery` but ships no concrete provider or discovery
implementation. Keep provider clients, credentials, TTLs, timeouts and public
address lookups in the host crate and inject the implementations into `inspect`
and `apply`.

A `SpfDns` implementation should use one provider call when the provider offers
an atomic RRset setter. If it can only add and remove values, a replacement may
be **two provider operations**; a failure between them can leave the RRset
partially changed. Map provider errors to fixed safe categories so request URLs,
response bodies or credentials are not propagated to the UI or logs. Hosts must
still avoid logging request bodies or secrets and should sanitize host-owned
error text they expose.

## Public address discovery

Implement `PublicAddressDiscovery` over the host's lookup service. A family
that the implementation returns as `None` is treated as unavailable: an update
removes that family's previously applied directive and clears it from the saved
addresses. Return `Err` when a transient lookup failure must abort the update
instead of removing the directive, and apply host timeouts and retries. The
browser preview uses fixture documentation addresses and performs no lookups.

## Topcoat UI

```rust,ignore
use topcoat::view::{Child, view};
use topcoat_spf::ui::spf_panel;

view! {
    spf_panel(
        snapshot: &snapshot,
        refresh_action: "/settings-spf",
        apply_action: "/settings-spf/apply",
        apply_method: "post",
        enable_action: "/settings-spf/enable",
        enable_method: "post",
        busy: busy,
        apply_fields: Child::new(view! {
            <input type="hidden" name="csrf" value=(csrf_token)>
        }),
        enable_fields: Child::new(view! {
            <input type="hidden" name="csrf" value=(csrf_token)>
        }),
    )
}
```

The Enable switch is checked exclusively from
`Snapshot::availability.spf_enabled`, the host's saved SPF setting. It never
reads or writes the DNS provider enabled flag. It defaults to off because
`Availability::default()` is unavailable; hosts must opt in. While SPF is off,
Refresh and Publish are disabled, but the switch itself remains usable so it can
turn SPF back on. When `availability.provider_enabled` is false, every SPF
control, including the switch, is disabled and the availability reason is shown.
The switch form submits `enabled=true` only when checked; hosts persist that as
the SPF setting, re-render and treat an absent field as SPF disabled. Do not
route the submitted value to DNS provider settings.

Include `ui::SPF_PANEL_JS` once on the page so the switch submits on change and
the controls react immediately. Without JavaScript, a `<noscript>` Save button
submits the same form.

`SPF_PANEL_JS` also adds the progress behavior. When Refresh or Publish starts a
native form submission, the submitting button immediately shows the installed
spinner, swaps its label to Refreshing… or Publishing…, and updates a polite
`role="status"` region for assistive technology. The other action and the Enable
switch are marked `aria-disabled`, and further panel submissions are ignored
while that navigation is in flight. No form field is disabled and the form's
action, method and values are left unchanged, so the submitted data is
preserved. A `pageshow`
listener clears a stale progress state when the browser restores the page from
its back/forward cache.

The panel:

* renders a flat, card-free layout with the SPF heading and the Enable switch as
  the master control, followed by public address and DNS record sections;
* aligns public and last-published IPv4/IPv6 values under fixed labels;
* aligns the Current and Proposed records as wrapping monospace text and shows
  the DNS record status beside the section heading as In sync, Update available
  or Unavailable;
* disables Refresh while SPF or the DNS provider is off, or a request is in
  flight;
* disables Publish whenever SPF or the provider is off, the host's `Availability`
  does not allow writes, no rewrite is needed (`Snapshot::needs_update` is
  false), the desired record cannot be computed, or a request is in flight; the
  match status is informational and does not disable Publish by itself, so a
  record that covers the public addresses can still be rewritten to drop a stale
  managed address;
* disables the Enable switch when the DNS provider is off or while `busy`, and
  shows a spinner in the action controls while `busy`; the server-rendered
  `busy` state is action-agnostic, so `SPF_PANEL_JS` adds the action-specific
  Refreshing…/Publishing… label when a form actually submits;
* shows a visible spinner and busy label immediately on Refresh or Publish
  submit, announces the state through a polite status region, avoids repeated
  panel submissions, and never disables the fields being submitted;
* leaves the displayed information readable when disabled and shows the hint
  "Enable to refresh or publish" while SPF is off; when the provider is off it
  shows the availability reason instead;
* groups Refresh and Publish at the bottom left on wider screens and stacks
  them on narrow screens; Refresh uses the quiet Ghost variant and Publish uses
  the theme-relative Secondary variant, which fits both light and dark host
  themes;
* explains Publish through a native `title` tooltip on the button instead of a
  separate paragraph: it publishes the current public addresses, removes
  previously applied addresses for unavailable families, and preserves other
  SPF mechanisms and TXT records;
* uses the installed Topcoat button, alert, spinner and switch components;
* forwards root attributes and uses semantic theme tokens for light and dark
  host themes;
* contains no authentication, storage or browser-runtime coupling; the
  optional `SPF_PANEL_JS` only submits the switch form, mirrors its state and
  adds the action progress state.

The `settings-table` and `spf-records-table` classes remain stable host styling
hooks on the address and record lists.

The refresh control is a GET form and the publish and enable controls are forms
whose methods default to POST. The enable form persists the SPF setting, not the
DNS provider setting. Supply hidden fields for CSRF tokens and any host context.
The host must authorize each endpoint again; hidden fields and disabled buttons
are not security boundaries.

### Styling and installed components

`src/components` contains unmodified Topcoat installs copied from the existing
application install, and `components.toml` records their genuine installation
hashes. Do not edit installed component files for application behaviour. Keep
the manifest in sync with `topcoat ui`.

Include this crate's source in the host's Tailwind class scan so the panel's
utility classes are generated. Hosts own the theme stylesheet and may add
classes through `attrs`.

## Authorization responsibilities

This crate does not authenticate or authorize anyone. Hosts must:

* authenticate and authorize every read and write, including the refresh form,
  the publish POST and the Enable switch POST, with the same access level as DNS
  settings;
* persist the Enable switch POST only to the SPF setting and leave the DNS
  provider enabled flag to its own settings surface;
* enforce CSRF protection on state-changing requests;
* validate the submitted domain, provider/zone relationship and any hidden
  fields again on the server;
* store provider credentials securely and encrypted at rest;
* never place credentials in `Snapshot`, UI props, logs, error text or browser
  storage;
* rate-limit and audit updates, and serialize them per domain;
* decide whether the operator may see the current record and public addresses.

`SpfAddressStore` is operational state. It is not authorization, and a missing
or stale value must never grant access.

## Atomicity and failure limits

There is no transaction spanning DNS and the host's storage.

* `SpfDns::replace_txt_records` may be implemented by a single provider setter
  or by multiple add/remove operations. A provider error can occur after some
  values changed. A host adapter that only supports additions and removals uses
  two operations.
* Provider read-back verifies the provider, not public DNS propagation. A
  verified write may not yet be visible to authoritative or recursive
  resolvers.
* If the read-back does not match, DNS may already be changed. The crate does
  not save the published addresses.
* If the DNS write succeeds and verification succeeds but the address-store save
  fails, DNS is updated and the stored addresses are stale. The returned
  `SpfError::SaveApplied` tells the operator to restore storage and retry.
* The service does not lock or deduplicate concurrent updates. Two requests can
  interleave; hosts must serialize per domain.
* No automatic rollback is attempted. A partial provider write must be
  inspected and corrected in the provider or by a later refresh/apply.
* A per-family discovery failure or non-public result is treated as
  unavailable, and the next successful update removes that family's previously
  applied directive. A discovery adapter that maps a transient lookup failure to
  `None` cannot distinguish it from an unavailable family; return `Err` instead
  when the update must abort.
* The service relies on the host's adapters for timeouts and retries.

## Reusing the rewrite independently

```rust
use topcoat_spf::{SpfAddresses, SpfError, replace_txt_records};

fn example() -> Result<(), SpfError> {
    let records = vec![
        "site-verification=abc".to_string(),
        "v=spf1 include:example.com -all".to_string(),
    ];
    let applied = SpfAddresses::default();
    let rewrite = replace_txt_records(
        &records,
        Some("203.0.113.8".parse().unwrap()),
        None,
        &applied,
    )?;
    assert_eq!(rewrite.records[0], "site-verification=abc");
    assert_eq!(
        rewrite.desired,
        "v=spf1 ip4:203.0.113.8 include:example.com -all"
    );
    Ok(())
}
```

`desired_spf_record` and `replace_txt_records` remove a saved host directive
when the corresponding address argument is `None`. Unrelated mechanisms,
networks and TXT values are retained. Passing no address for either family
returns `SpfError::NoPublicAddress` instead of removing every managed directive.

## Validation

Run:

```sh
cargo fmt --check
cargo check --all-targets --no-default-features
cargo check --all-targets
cargo check --all-targets --no-default-features --features ui
cargo check --all-targets --no-default-features --features preview
cargo check --example preview --features preview
cargo check --bin preview --features preview
cargo clippy --all-targets --all-features
cargo test --no-default-features
cargo test --no-default-features --features preview
cargo test
```

Tests cover the extracted rewrite rules, unrelated-TXT preservation,
idempotence, multiple/invalid record rejection, complete-set verification,
service ordering, the pre-write settings re-check, independent SPF/provider
gating for refresh and writes, host write-policy gating, verification/save
failures, the UI's flat sections, record status, disabled hint and Enable
switch, refresh and publish gating, the rendered action progress hooks and busy
loading markup, and the preview's fixture-to-snapshot construction, fixture
address use, partial-family removal and saved-family clearing,
both-unavailable refusal, empty and failed discovery, timeout handling and
disabled-inspection skip using injected fake discovery (no external network).
Bounded HTTP smoke tests assert that the enabled initial page returns its
loading shell without waiting for the panel, that disabled settings render the
panel immediately, and that the `/panel` fragment endpoint returns the rendered
panel. External DNS provider operations, public-address services and browser
rendering are not covered by automated tests; the crate and its tests use
fixtures only.
`topcoat dev` is a long-running server, so it is not part of the automated
checks; run `topcoat dev` and open <http://127.0.0.1:3000/> for a manual check.
