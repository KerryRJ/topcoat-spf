//! Reusable, host-styled Topcoat panel for inspecting and publishing SPF changes.
//!
//! The panel is server-rendered and deliberately free of host authentication,
//! browser runtime globals and storage access. The host supplies the refresh,
//! publish and enable endpoints and any hidden fields (for example CSRF
//! tokens). The panel only renders the provided [`Snapshot`]; server-side
//! authorization and a fresh [`WritePolicy`](crate::WritePolicy) check remain
//! mandatory.

use crate::{
    Snapshot,
    components::{
        alert::{AlertVariant, alert, alert_description},
        button::{ButtonSize, ButtonVariant, button},
        spinner::spinner,
        switch::switch,
    },
};
use topcoat::{
    Result,
    context::Cx,
    icon::{IconData, icon, iconify::iconify_icon},
    view::{Attributes, Child, View, attributes, class, component, view},
};

const REFRESH: IconData = iconify_icon!("lucide:refresh-cw");
const PUBLISH: IconData = iconify_icon!("lucide:cloud-upload");

/// Browser behavior for the Enable switch and action progress.
///
/// Include it once on pages that render [`spf_panel`]. It submits the switch
/// form on change and immediately disables the panel's controls while the
/// switch is off. When a Refresh or Publish form starts a native submission, it
/// immediately shows the action's spinner and accessible busy label, and it
/// ignores further panel submissions until navigation completes. Form fields
/// are never disabled, so the submitted form data and method are preserved. A
/// bfcache restore (`pageshow`) clears a stale progress state.
///
/// Panels inserted after the initial page render work through the same event
/// delegation. Dispatch an `spf:panel-loaded` event on `document` after the new
/// markup is inserted so the shared script re-runs its initial switch
/// synchronization.
pub const SPF_PANEL_JS: &str = include_str!("ui.js");

/// Whether the Refresh control must be disabled for this snapshot.
///
/// Refresh is disabled while a request is in flight and unless both the SPF
/// setting and the DNS provider are enabled. Host write policy does not disable
/// this read-only control.
fn refresh_is_disabled(snapshot: &Snapshot, busy: bool) -> bool {
    busy || !snapshot.availability.can_refresh()
}

/// Whether the Publish control must be disabled for this snapshot.
///
/// Publish is disabled while a request is in flight, when SPF or the provider
/// is disabled, when the host's availability state does not allow writes, when
/// the desired value cannot be computed, or when publishing would not change
/// the SPF value. The Enable switch maps exclusively to
/// [`Availability::spf_enabled`](crate::Availability::spf_enabled), so switching
/// it off disables Publish without changing the provider setting.
///
/// [`Snapshot::matches`] is an informational coverage status and does not
/// disable Publish by itself, because a record can contain the public addresses
/// and still need a rewrite to remove a stale managed address.
pub fn apply_is_disabled(snapshot: &Snapshot, busy: bool) -> bool {
    busy || !snapshot.availability.can_write()
        || snapshot.desired.is_none()
        || !snapshot.needs_update
}

/// Render the SPF panel.
///
/// `refresh_action` is used by a GET form and `apply_action` by the
/// `apply_method` form (normally POST). `enable_action` receives the Enable
/// switch form (normally POST): the host persists the submitted `enabled` field
/// as its SPF enabled setting and re-renders. The switch is checked from
/// [`Availability::spf_enabled`](crate::Availability::spf_enabled) only; it must
/// never write the DNS provider enabled setting. `refresh_fields`, `apply_fields`
/// and `enable_fields` are inserted inside the respective forms, so the host can
/// add CSRF tokens or other context.
///
/// While SPF is off, Refresh and Publish are disabled, the snapshot stays
/// readable and the panel shows an "Enable to refresh or publish" hint; the
/// switch itself stays usable so it can turn SPF back on. When the provider is
/// disabled, every control, including the switch, is disabled and the
/// availability reason is shown. `busy` disables the switch and both actions and
/// swaps both action icons for a spinner; the host owns that in-flight state and
/// re-renders after the operation. Because `busy` is action-agnostic, the
/// server-rendered state keeps the action labels; [`SPF_PANEL_JS`] supplies the
/// action-specific "Refreshing…"/"Publishing…" label as soon as a form submits.
///
/// Include [`SPF_PANEL_JS`] once on the page so the switch submits on change and
/// the controls react immediately. Without JavaScript, a `<noscript>` Save
/// button in the switch form submits the same field.
///
/// The panel forwards `attrs` to its root `<section>` and uses semantic Topcoat
/// theme tokens, so hosts control light/dark styling. Hosts must include this
/// crate's source in their Tailwind class scan.
#[component]
pub async fn spf_panel(
    cx: &Cx,
    snapshot: &Snapshot,
    refresh_action: &str,
    apply_action: &str,
    enable_action: &str,
    #[default("post")] apply_method: &str,
    #[default("post")] enable_method: &str,
    #[default] busy: bool,
    #[default] mut attrs: Attributes,
    #[default] refresh_fields: Child<'_>,
    #[default] apply_fields: Child<'_>,
    #[default] enable_fields: Child<'_>,
) -> Result<impl View> {
    let current = snapshot
        .current
        .as_deref()
        .unwrap_or("No SPF TXT record found.");
    let public_ipv4 = snapshot
        .public_ipv4
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "Unavailable".into());
    let public_ipv6 = snapshot
        .public_ipv6
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "Unavailable".into());
    let applied_ipv4 = snapshot
        .applied
        .ipv4
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "None".into());
    let applied_ipv6 = snapshot
        .applied
        .ipv6
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "None".into());
    let error = snapshot.error.as_deref().unwrap_or_default();
    let reason = snapshot
        .availability
        .reason
        .as_deref()
        .filter(|reason| !reason.trim().is_empty())
        .unwrap_or("SPF updates are unavailable. Enable and configure the DNS provider.");
    let apply_disabled = apply_is_disabled(snapshot, busy);
    let refresh_disabled = refresh_is_disabled(snapshot, busy);
    let spf_enabled = snapshot.availability.spf_enabled;
    let provider_enabled = snapshot.availability.provider_enabled;
    let switch_disabled = busy || !provider_enabled;
    let match_label = if snapshot.matches {
        "Current SPF record includes the public IP addresses"
    } else {
        "Current SPF record is missing one or more public IP addresses"
    };
    let (status_label, status_class) =
        if !snapshot.availability.can_write() || snapshot.desired.is_none() {
            ("Unavailable", "text-muted-foreground")
        } else if snapshot.needs_update {
            ("Update available", "text-foreground")
        } else {
            ("In sync", "text-primary")
        };
    let status_description = format!("DNS record status: {status_label}. {match_label}");

    Ok(view! {
        <section
            class=(class!("flex min-w-0 flex-col gap-6", attrs.remove("class")))
            aria-busy=(if busy { "true" } else { "false" })
            data-spf-panel=""
            (attrs)
        >
            if !error.is_empty() {
                alert(
                    variant: AlertVariant::Destructive,
                    attrs: attributes! { role="status" aria-live="polite" },
                    alert_description((error))
                )
            }

            <header class="flex flex-col gap-4">
                <div class="flex min-w-0 flex-col gap-1.5">
                    <h2 class="text-lg font-semibold tracking-tight">"SPF TXT record"</h2>
                </div>

                <form
                    action=(enable_action)
                    method=(enable_method)
                    class="flex flex-col gap-1.5"
                >
                    (enable_fields)
                    <div class="flex items-center gap-2">
                        <label
                            class="text-sm leading-none font-medium select-none"
                            for="spf-enabled"
                        >
                            "Enable"
                        </label>
                        switch(attrs: attributes! {
                            id="spf-enabled"
                            name="enabled"
                            value="true"
                            checked=(spf_enabled)
                            disabled=(switch_disabled)
                            data-spf-enabled=""
                        })
                    </div>
                    <noscript>
                        button(
                            variant: ButtonVariant::Secondary,
                            size: ButtonSize::Sm,
                            attrs: attributes! { type="submit" disabled=(switch_disabled) },
                            "Save"
                        )
                    </noscript>
                </form>
            </header>

            <section class="flex flex-col gap-2" aria-labelledby="spf-public-addresses-heading">
                <h3 id="spf-public-addresses-heading" class="text-sm font-semibold">
                    "Public IP addresses"
                </h3>
                <dl class="settings-table flex flex-col gap-2 text-sm">
                    <div class="grid grid-cols-[4.5rem_minmax(0,1fr)] items-baseline gap-x-4">
                        <dt class="text-muted-foreground">"IPv4"</dt>
                        <dd class="flex min-w-0 flex-col gap-0.5">
                            <span id="public-ipv4" class="font-mono break-all">(public_ipv4)</span>
                            <span class="text-xs text-muted-foreground">
                                "Last applied "
                                <span id="applied-ipv4" class="font-mono text-foreground">(applied_ipv4)</span>
                            </span>
                        </dd>
                    </div>
                    <div class="grid grid-cols-[4.5rem_minmax(0,1fr)] items-baseline gap-x-4">
                        <dt class="text-muted-foreground">"IPv6"</dt>
                        <dd class="flex min-w-0 flex-col gap-0.5">
                            <span id="public-ipv6" class="font-mono break-all">(public_ipv6)</span>
                            <span class="text-xs text-muted-foreground">
                                "Last applied "
                                <span id="applied-ipv6" class="font-mono text-foreground">(applied_ipv6)</span>
                            </span>
                        </dd>
                    </div>
                </dl>
            </section>

            <section class="flex flex-col gap-2" aria-labelledby="spf-dns-record-heading">
                <div class="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                    <h3 id="spf-dns-record-heading" class="text-sm font-semibold">
                        "DNS record"
                    </h3>
                    <span
                        id="record-match-status"
                        class=(class!(
                            "inline-flex items-center gap-1.5 text-xs font-medium",
                            status_class,
                        ))
                        aria-label=(status_description)
                    >
                        <span class="size-1.5 rounded-full bg-current" aria-hidden="true"></span>
                        (status_label)
                    </span>
                </div>
                <p class="text-xs text-muted-foreground">
                    "Record name "
                    <span id="spf-record-name" class="font-mono break-all text-foreground">
                        (snapshot.domain.as_str())
                    </span>
                </p>
                <dl class="spf-records-table flex flex-col gap-3 text-sm">
                    <div class="grid grid-cols-1 gap-1 sm:grid-cols-[5.5rem_minmax(0,1fr)] sm:items-baseline sm:gap-x-4">
                        <dt class="text-muted-foreground">"Current"</dt>
                        <dd
                            id="current-record"
                            class="min-w-0 font-mono break-words whitespace-pre-wrap"
                        >
                            (current)
                        </dd>
                    </div>
                    <div class="grid grid-cols-1 gap-1 sm:grid-cols-[5.5rem_minmax(0,1fr)] sm:items-baseline sm:gap-x-4">
                        <dt class="text-muted-foreground">"Proposed"</dt>
                        <dd
                            id="desired-record"
                            class="min-w-0 font-mono break-words whitespace-pre-wrap"
                        >
                            (snapshot.desired.as_deref().unwrap_or("No proposal available."))
                        </dd>
                    </div>
                </dl>
            </section>

            <div class="border-t border-border" aria-hidden="true"></div>

            <div class="flex flex-col gap-3">
                <div class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-start">
                    <form
                        action=(refresh_action)
                        method="get"
                        class="flex sm:inline-flex"
                        data-spf-action-form="refresh"
                    >
                        (refresh_fields)
                        button(
                            variant: ButtonVariant::Ghost,
                            attrs: attributes! {
                                id="refresh-dns"
                                type="submit"
                                class="w-full justify-center sm:w-auto"
                                disabled=(refresh_disabled)
                                data-spf-action="refresh"
                                data-spf-idle-label="Refresh"
                                data-spf-busy-label="Refreshing…"
                                data-spf-control=""
                                data-spf-disabled=(refresh_disabled)
                            },
                            spinner(attrs: attributes! {
                                class=(if busy { "size-4" } else { "hidden size-4" })
                                data-spf-spinner=""
                                aria-hidden="true"
                            })
                            icon(
                                data: REFRESH,
                                attrs: attributes! {
                                    class=(if busy { "hidden size-4" } else { "size-4" })
                                    data-spf-icon=""
                                }
                            )
                            <span data-spf-label="">"Refresh"</span>
                        )
                    </form>
                    <form
                        action=(apply_action)
                        method=(apply_method)
                        class="flex sm:inline-flex"
                        data-spf-action-form="publish"
                    >
                        (apply_fields)
                        button(
                            variant: ButtonVariant::Secondary,
                            attrs: attributes! {
                                id="update-spf"
                                type="submit"
                                class="w-full justify-center sm:w-auto"
                                disabled=(apply_disabled)
                                title="Publish current public addresses. Removes previously applied addresses for unavailable families; preserves other SPF mechanisms and TXT records."
                                data-spf-action="publish"
                                data-spf-idle-label="Publish"
                                data-spf-busy-label="Publishing…"
                                data-spf-control=""
                                data-spf-disabled=(apply_disabled)
                            },
                            spinner(attrs: attributes! {
                                class=(if busy { "size-4" } else { "hidden size-4" })
                                data-spf-spinner=""
                                aria-hidden="true"
                            })
                            icon(
                                data: PUBLISH,
                                attrs: attributes! {
                                    class=(if busy { "hidden size-4" } else { "size-4" })
                                    data-spf-icon=""
                                }
                            )
                            <span data-spf-label="">"Publish"</span>
                        )
                    </form>
                </div>

                <p
                    class="sr-only"
                    data-spf-status=""
                    role="status"
                    aria-live="polite"
                    aria-atomic="true"
                ></p>

                if !provider_enabled {
                    <p class="text-sm text-muted-foreground">(reason)</p>
                } else if !spf_enabled {
                    <p class="text-sm text-muted-foreground">"Enable to refresh or publish"</p>
                } else if !snapshot.availability.write_available {
                    <p class="text-sm text-muted-foreground">(reason)</p>
                }
            </div>
        </section>
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Availability;

    fn snapshot() -> Snapshot {
        Snapshot {
            domain: crate::DomainName::new("example.com").unwrap(),
            source: "DNS provider".into(),
            current: Some("v=spf1 -all".into()),
            desired: Some(crate::SpfRecordText::new("v=spf1 ip4:203.0.113.8 -all").unwrap()),
            availability: Availability::available(),
            needs_update: true,
            public_ipv4: None,
            public_ipv6: None,
            applied: Default::default(),
            matches: false,
            error: None,
        }
    }

    fn availability(spf_enabled: bool, provider_enabled: bool) -> Availability {
        Availability {
            spf_enabled,
            provider_enabled,
            write_available: true,
            reason: Some("Enable SPF and the DNS provider.".into()),
        }
    }

    #[test]
    fn apply_is_disabled_by_host_availability_busy_or_missing_update() {
        let pending = snapshot();
        assert!(pending.needs_update);
        assert!(!apply_is_disabled(&pending, false));
        assert!(apply_is_disabled(&pending, true));

        let mut disabled = pending.clone();
        disabled.availability = Availability::disabled("Enable the provider.");
        assert!(apply_is_disabled(&disabled, false));

        let mut up_to_date = pending.clone();
        up_to_date.needs_update = false;
        assert!(apply_is_disabled(&up_to_date, false));

        let mut uncomputed = pending;
        uncomputed.desired = None;
        assert!(apply_is_disabled(&uncomputed, false));
    }

    #[test]
    fn refresh_and_publish_require_spf_and_provider() {
        assert!(!refresh_is_disabled(&snapshot(), false));
        assert!(!apply_is_disabled(&snapshot(), false));
        assert!(refresh_is_disabled(&snapshot(), true));
        assert!(apply_is_disabled(&snapshot(), true));

        for spf_enabled in [false, true] {
            for provider_enabled in [false, true] {
                let mut state = snapshot();
                state.availability = availability(spf_enabled, provider_enabled);
                let expected = !(spf_enabled && provider_enabled);
                assert_eq!(
                    refresh_is_disabled(&state, false),
                    expected,
                    "refresh for spf_enabled={spf_enabled} provider_enabled={provider_enabled}"
                );
                assert_eq!(
                    apply_is_disabled(&state, false),
                    expected,
                    "publish for spf_enabled={spf_enabled} provider_enabled={provider_enabled}"
                );
            }
        }
    }

    #[test]
    fn matching_coverage_does_not_disable_apply_when_the_desired_record_differs() {
        let mut stale = snapshot();
        stale.matches = true;
        assert!(stale.needs_update);
        assert!(!apply_is_disabled(&stale, false));

        let mut up_to_date = snapshot();
        up_to_date.matches = true;
        up_to_date.needs_update = false;
        assert!(apply_is_disabled(&up_to_date, false));
    }

    #[test]
    fn host_write_policy_does_not_disable_the_read_only_refresh_control() {
        let mut policy = snapshot();
        policy.availability.write_available = false;
        assert!(!refresh_is_disabled(&policy, false));
        assert!(apply_is_disabled(&policy, false));
    }

    use topcoat::{context::Cx, view::ViewExt};

    async fn render_panel_with(snapshot: &Snapshot, busy: bool) -> String {
        let cx = &Cx::default();
        view! {
            spf_panel(
                snapshot: snapshot,
                refresh_action: "/refresh",
                apply_action: "/publish",
                enable_action: "/enable",
                busy: busy,
            )
        }
        .single()
        .await
        .expect("render the SPF panel")
        .render(cx)
    }

    async fn render_panel(snapshot: &Snapshot) -> String {
        render_panel_with(snapshot, false).await
    }

    fn tag<'a>(html: &'a str, needle: &str) -> &'a str {
        let attribute = html.find(needle).expect("attribute is rendered");
        let start = html[..attribute].rfind('<').expect("tag starts");
        let end = html[attribute..].find('>').expect("tag closes") + attribute;
        &html[start..=end]
    }

    fn button<'a>(html: &'a str, id: &str) -> &'a str {
        let marker = format!("id=\"{id}\"");
        let attribute = html.find(&marker).expect("button is rendered");
        let start = html[..attribute].rfind('<').expect("button starts");
        let end = html[start..].find("</button>").expect("button closes") + start;
        &html[start..end + "</button>".len()]
    }

    fn has_class(tag: &str, name: &str) -> bool {
        let marker = "class=\"";
        let start = tag.find(marker).expect("class is rendered") + marker.len();
        let end = tag[start..].find('"').expect("class closes") + start;
        tag[start..end]
            .split_whitespace()
            .any(|class| class == name)
    }

    #[tokio::test]
    async fn panel_renders_an_accessible_enable_switch_and_publish_action() {
        let html = render_panel(&snapshot()).await;
        let switch_html = tag(&html, "id=\"spf-enabled\"");

        assert!(switch_html.contains("role=\"switch\""));
        assert!(switch_html.contains("name=\"enabled\""));
        assert!(switch_html.contains("value=\"true\""));
        assert!(switch_html.contains(" checked=\""));
        assert!(!switch_html.contains(" disabled=\""));
        assert!(html.contains("action=\"/enable\""));
        assert!(html.contains(">Publish"));
        assert!(!html.contains(">Apply"));
        assert!(!html.contains("<fieldset"));
        assert!(!tag(&html, "id=\"refresh-dns\"").contains(" disabled=\""));
        assert!(!tag(&html, "id=\"update-spf\"").contains(" disabled=\""));
        assert!(tag(&html, "id=\"update-spf\"").contains("data-spf-control"));
    }

    #[tokio::test]
    async fn spf_off_keeps_the_switch_usable_and_disables_the_controls() {
        let mut disabled = snapshot();
        disabled.availability = Availability::spf_disabled("SPF is off.");
        let html = render_panel(&disabled).await;
        let switch_html = tag(&html, "id=\"spf-enabled\"");

        assert!(!switch_html.contains(" checked=\""));
        assert!(!switch_html.contains(" disabled=\""));
        assert!(tag(&html, "id=\"refresh-dns\"").contains(" disabled=\""));
        assert!(tag(&html, "id=\"update-spf\"").contains(" disabled=\""));
        assert!(html.contains("Enable to refresh or publish"));
    }

    #[tokio::test]
    async fn provider_off_disables_every_control_including_the_switch() {
        let mut disabled = snapshot();
        disabled.availability =
            Availability::provider_disabled(true, "The DNS provider is disabled.");
        let html = render_panel(&disabled).await;
        let switch_html = tag(&html, "id=\"spf-enabled\"");

        // The switch still reflects the independent saved SPF setting.
        assert!(switch_html.contains(" checked=\""));
        assert!(switch_html.contains(" disabled=\""));
        assert!(tag(&html, ">Save").contains(" disabled=\""));
        assert!(tag(&html, "id=\"refresh-dns\"").contains(" disabled=\""));
        assert!(tag(&html, "id=\"update-spf\"").contains(" disabled=\""));
        assert!(html.contains("The DNS provider is disabled."));
        assert!(!html.contains("Enable to refresh or publish"));
    }

    #[tokio::test]
    async fn actions_render_progress_hooks_for_progressive_enhancement() {
        let html = render_panel(&snapshot()).await;
        let refresh = button(&html, "refresh-dns");
        let publish = button(&html, "update-spf");

        assert!(html.contains("data-spf-action-form=\"refresh\""));
        assert!(html.contains("data-spf-action-form=\"publish\""));
        assert!(html.contains("data-spf-status"));
        assert!(html.contains("role=\"status\""));
        assert!(html.contains("aria-live=\"polite\""));

        assert!(refresh.contains("data-spf-action=\"refresh\""));
        assert!(refresh.contains("data-spf-idle-label=\"Refresh\""));
        assert!(refresh.contains("data-spf-busy-label=\"Refreshing…\""));
        assert!(refresh.contains("data-spf-spinner"));
        assert!(refresh.contains("data-spf-icon"));
        assert!(refresh.contains("data-spf-label"));
        assert!(refresh.contains(">Refresh</span>"));
        assert!(has_class(tag(refresh, "data-spf-spinner"), "hidden"));
        assert!(!has_class(tag(refresh, "data-spf-icon"), "hidden"));

        assert!(publish.contains("data-spf-action=\"publish\""));
        assert!(publish.contains("data-spf-idle-label=\"Publish\""));
        assert!(publish.contains("data-spf-busy-label=\"Publishing…\""));
        assert!(publish.contains("data-spf-spinner"));
        assert!(publish.contains("data-spf-icon"));
        assert!(publish.contains("data-spf-label"));
        assert!(publish.contains(">Publish</span>"));
        assert!(publish.contains(
            "title=\"Publish current public addresses. Removes previously applied addresses for unavailable families; preserves other SPF mechanisms and TXT records.\""
        ));
        assert!(!html.contains("Publishing replaces the previously applied addresses"));
        assert!(has_class(tag(publish, "data-spf-spinner"), "hidden"));
        assert!(!has_class(tag(publish, "data-spf-icon"), "hidden"));
    }

    #[test]
    fn panel_script_blocks_repeat_submits_and_restores_cached_pages() {
        assert!(SPF_PANEL_JS.contains("data-spf-submitting"));
        assert!(SPF_PANEL_JS.contains("preventDefault"));
        assert!(SPF_PANEL_JS.contains("pageshow"));
        assert!(SPF_PANEL_JS.contains("aria-busy"));
        assert!(SPF_PANEL_JS.contains("spf:panel-loaded"));
    }

    #[tokio::test]
    async fn busy_disables_both_actions_and_the_switch() {
        let html = render_panel_with(&snapshot(), true).await;
        let switch_html = tag(&html, "id=\"spf-enabled\"");

        assert!(switch_html.contains(" disabled=\""));
        assert!(tag(&html, ">Save").contains(" disabled=\""));
        assert!(tag(&html, "id=\"refresh-dns\"").contains(" disabled=\""));
        assert!(tag(&html, "id=\"update-spf\"").contains(" disabled=\""));
        assert!(html.contains("aria-busy=\"true\""));
    }

    #[tokio::test]
    async fn busy_renders_the_spinner_in_place_of_each_action_icon() {
        let html = render_panel_with(&snapshot(), true).await;

        assert!(!has_class(tag(&html, "data-spf-spinner"), "hidden"));
        assert!(has_class(tag(&html, "data-spf-icon"), "hidden"));
        assert!(html.contains("Refreshing…"));
        assert!(html.contains("Publishing…"));
    }

    #[tokio::test]
    async fn panel_uses_flat_sections_with_aligned_monospace_records() {
        let html = render_panel(&snapshot()).await;
        let root = tag(&html, "data-spf-panel");

        assert!(!root.contains("bg-card"));
        assert!(!root.contains("rounded-"));
        assert!(html.contains("Public IP addresses"));
        assert!(html.contains("DNS record"));
        assert!(html.contains(">Current"));
        assert!(html.contains(">Proposed"));
        assert!(html.contains("Update available"));

        let current = tag(&html, "id=\"current-record\"");
        let desired = tag(&html, "id=\"desired-record\"");
        assert!(current.contains("font-mono"));
        assert!(desired.contains("font-mono"));
        assert!(current.contains("break-words"));
        assert!(desired.contains("break-words"));
        assert!(tag(&html, "id=\"refresh-dns\"").contains("sm:w-auto"));
    }

    #[tokio::test]
    async fn record_status_reflects_sync_and_unavailable_states() {
        let mut synced = snapshot();
        synced.matches = true;
        synced.needs_update = false;
        let html = render_panel(&synced).await;
        assert!(html.contains("In sync"));

        let mut unavailable = snapshot();
        unavailable.availability = Availability::spf_disabled("SPF is off.");
        let html = render_panel(&unavailable).await;
        assert!(html.contains("Unavailable"));
        assert!(html.contains("Enable to refresh or publish"));
        assert!(html.contains("v=spf1 -all"));
        assert!(html.contains("v=spf1 ip4:203.0.113.8 -all"));
        assert!(tag(&html, "id=\"refresh-dns\"").contains(" disabled=\""));
        assert!(tag(&html, "id=\"update-spf\"").contains(" disabled=\""));
    }
}
