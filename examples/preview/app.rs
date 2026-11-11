//! Runnable browser preview for the reusable SPF panel.
//!
//! The page renders a [`Snapshot`](topcoat_spf::Snapshot) through
//! [`spf_panel`]. The DNS record, previous addresses and public IPv4/IPv6
//! addresses are fixtures supplied through the core traits; the preview
//! contacts no external services. Form actions never write DNS, contact a
//! provider or use storage for records. The `enabled` query parameter selects
//! the independent SPF setting and `provider` selects the DNS provider state. A
//! preview-only switch simulates the saved DNS provider setting: turning it off
//! disables the SPF switch, Refresh and Publish, and turning it back on restores
//! the independent SPF setting. `published=1` records a simulated successful
//! Publish, so the next snapshot reports Current and Proposed as equal.
//!
//! The page uses a fixture DNS source, fixture previous addresses and a fixture
//! public-address source from the shared preview module, and builds the proposed
//! record through the library's normal inspection and rewrite functions. Refresh
//! reloads the page and rebuilds the snapshot from the fixtures; while
//! `published=1` is present it rebuilds the published fixture state instead.
//!
//! When the panel is loaded asynchronously, the initial response is a fast shell
//! with the header, theme control, provider simulation and an accessible
//! spinner/status. The browser then loads the rendered panel from `GET /panel`
//! so rendering cannot hide the page. Disabled settings render the panel
//! immediately. `?full=1` renders the panel during the page request as a
//! no-JavaScript fallback.
//!
//! The same module backs the `preview` development binary and the `preview`
//! example. Run the development server with:
//!
//! ```sh
//! topcoat dev
//! ```
//!
//! or run the example directly with:
//!
//! ```sh
//! cargo run --example preview --features preview
//! ```
//!
//! and open the configured listener: `127.0.0.1:3000` by default, or the
//! `HOST`/`PORT` values from the nearest `.env`.

use std::{env, fs, io};

use tokio::net::TcpListener;
use topcoat::{
    Result,
    context::Cx,
    icon::{IconData, icon, iconify::iconify_icon},
    router::{
        Router, Slot,
        content::Form,
        error::{SeeOther, see_other},
        layout, page, query_params, route,
    },
    view::{Child, Unescaped, View, ViewExt, ViewHandle, attributes, view},
};
use topcoat_spf::{
    Availability, Snapshot,
    components::{
        alert::{AlertVariant, alert, alert_description, alert_title},
        button::{ButtonSize, ButtonVariant, button},
        spinner::spinner,
        switch::switch,
    },
    ui::spf_panel,
};

/// Rendered by `build.rs` only when the `preview` feature is enabled.
const TAILWIND_CSS: &str = include_str!(concat!(env!("OUT_DIR"), "/tailwind.css"));

/// Switches the panel controls and submits the Enable form on change.
const PANEL_SCRIPT: &str = topcoat_spf::ui::SPF_PANEL_JS;

/// Submits the preview-only DNS provider simulation form on change.
const PROVIDER_SCRIPT: &str = r#"
(() => {
  document.addEventListener("change", (event) => {
    const input = event.target.closest("[data-preview-provider]");
    if (!input) return;
    input.form?.requestSubmit();
  });
})();
"#;

/// Replaces the initial loading shell with the server-rendered panel after the
/// fixture inspection finishes. The shell itself is server-rendered so it is
/// visible before this request starts.
const PANEL_LOAD_SCRIPT: &str = r#"
(() => {
  const load = () => {
    const region = document.querySelector("[data-spf-panel-region]");
    if (!region) return;

    const src = region.dataset.spfPanelSrc;
    if (!src) return;

    const showError = () => {
      region.removeAttribute("aria-busy");
      const loading = region.querySelector("[data-spf-loading]");
      if (loading) loading.hidden = true;
      const error = region.querySelector("[data-spf-load-error]");
      if (error) error.hidden = false;
    };

    fetch(src, {
      headers: { Accept: "text/html" },
      cache: "no-store",
    })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.text();
      })
      .then((html) => {
        region.innerHTML = html;
        region.removeAttribute("aria-busy");
        document.dispatchEvent(new CustomEvent("spf:panel-loaded"));
      })
      .catch(showError);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", load);
  } else {
    load();
  }

  // Retry a load that was still in progress when the page entered the bfcache.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) load();
  });
})();
"#;

const SUN: IconData = iconify_icon!("lucide:sun");
const MOON: IconData = iconify_icon!("lucide:moon");

/// Applies the stored theme before first paint and wires the header toggle.
/// Dark mode is the default when no valid preference is stored.
const THEME_SCRIPT: &str = r#"
(() => {
  const root = document.documentElement;
  const key = "topcoat-spf-theme";

  let stored = null;
  try {
    stored = localStorage.getItem(key);
  } catch {
    // Storage can be unavailable; dark remains the default.
  }

  root.classList.toggle("dark", stored !== "light");

  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle");
    if (!button) return;

    const sync = () => {
      const dark = root.classList.contains("dark");
      button.setAttribute("aria-pressed", String(dark));
      button.setAttribute(
        "title",
        dark ? "Switch to light mode" : "Switch to dark mode",
      );
    };

    sync();
    button.addEventListener("click", () => {
      const dark = root.classList.toggle("dark");
      try {
        localStorage.setItem(key, dark ? "dark" : "light");
      } catch {
        // Keep the in-page toggle working even when persistence fails.
      }
      sync();
    });
  });
})();
"#;

#[query_params(error = bad_request)]
struct PreviewQuery {
    notice: Option<String>,
    /// `1` keeps the independent SPF setting on; `0` turns SPF off.
    enabled: Option<String>,
    /// `1` keeps the DNS provider enabled; `0` disables the provider and every
    /// SPF control, including the switch.
    provider: Option<String>,
    /// `1` renders the panel during the page request instead of using the
    /// asynchronous loading shell. This is the no-JavaScript fallback.
    full: Option<String>,
    /// `1` shows the fixture state after a simulated successful Publish: the
    /// fixture DNS record and last-applied addresses hold the proposed values.
    published: Option<String>,
}

fn preview_availability(spf_enabled: bool, provider_enabled: bool) -> Availability {
    match (spf_enabled, provider_enabled) {
        (true, true) => Availability::available(),
        (false, true) => Availability::spf_disabled(
            "SPF is disabled. Turn on Enable to refresh and publish changes.",
        ),
        (true, false) => Availability::provider_disabled(
            true,
            "The DNS provider is disabled. Enable it in DNS settings; SPF controls are unavailable.",
        ),
        (false, false) => Availability::disabled(
            "SPF and the DNS provider are disabled. Enable both in their settings.",
        ),
    }
}

#[layout("/")]
async fn layout(cx: &Cx, slot: Slot<'_>) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en" class="dark">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"topcoat-spf preview"</title>
                <noscript>
                    <style>"[data-spf-loading] { display: none; }"</style>
                </noscript>
                <style>(Unescaped::new_unchecked(TAILWIND_CSS))</style>
                <script>(Unescaped::new_unchecked(THEME_SCRIPT))</script>
                <script>(Unescaped::new_unchecked(PANEL_SCRIPT))</script>
                <script>(Unescaped::new_unchecked(PROVIDER_SCRIPT))</script>
                <script>(Unescaped::new_unchecked(PANEL_LOAD_SCRIPT))</script>
            </head>
            <body>
                (slot)
            </body>
        </html>
    })
}

/// Render the public-address notice and the panel as one fragment. The result
/// is owned so it can be returned from the asynchronous fragment endpoint or
/// embedded in the initial page without borrowing a request-local snapshot.
async fn panel_contents(
    cx: &Cx,
    snapshot: &Snapshot,
    spf_param: &str,
    provider_param: &str,
    published: bool,
    full: bool,
) -> Result<ViewHandle> {
    let discovery_note =
        topcoat_spf::preview::discovery_note(snapshot).filter(|_| snapshot.error.is_none());
    let panel = view! {
        if let Some(note) = discovery_note {
            alert(
                variant: AlertVariant::Neutral,
                alert_title("Public addresses")
                alert_description((note))
            )
        }

        spf_panel(
            snapshot: snapshot,
            refresh_action: "/",
            apply_action: "/apply",
            enable_action: "/enable",
            apply_method: "post",
            enable_method: "post",
            busy: false,
            refresh_fields: Child::new(view! {
                <input type="hidden" name="enabled" value=(spf_param)>
                <input type="hidden" name="provider" value=(provider_param)>
                if published {
                    <input type="hidden" name="published" value="1">
                }
                if full {
                    <input type="hidden" name="full" value="1">
                }
            }),
            apply_fields: Child::new(view! {
                <input type="hidden" name="enabled" value=(spf_param)>
                <input type="hidden" name="provider" value=(provider_param)>
                if published {
                    <input type="hidden" name="published" value="1">
                }
                if full {
                    <input type="hidden" name="full" value="1">
                }
            }),
            enable_fields: Child::new(view! {
                <input type="hidden" name="provider" value=(provider_param)>
                if published {
                    <input type="hidden" name="published" value="1">
                }
                if full {
                    <input type="hidden" name="full" value="1">
                }
            }),
        )
    };

    panel.single().await
}

#[page("/")]
async fn preview(cx: &Cx) -> Result<impl View> {
    let query = query_params::<PreviewQuery>(cx)?;
    let applied = query.notice.as_deref() == Some("applied");
    let published = query.published.as_deref() == Some("1");
    let spf_enabled = query.enabled.as_deref() != Some("0");
    let provider_enabled = query.provider.as_deref() != Some("0");
    let spf_param = if spf_enabled { "1" } else { "0" };
    let provider_param = if provider_enabled { "1" } else { "0" };
    let availability = preview_availability(spf_enabled, provider_enabled);

    // Disabled settings skip inspection, and `?full=1` is the no-JavaScript
    // fallback. Both render the panel during the page request. Otherwise the
    // shell renders immediately and the browser loads the panel from `/panel`.
    let blocking = !availability.can_refresh() || query.full.as_deref() == Some("1");
    let contents = if blocking {
        let snapshot = if published {
            topcoat_spf::preview::published_snapshot(availability).await
        } else {
            topcoat_spf::preview::snapshot(availability).await
        };
        Some(panel_contents(cx, &snapshot, spf_param, provider_param, published, true).await?)
    } else {
        None
    };
    let panel_src = format!(
        "/panel?enabled={spf_param}&provider={provider_param}{}",
        if published { "&published=1" } else { "" }
    );
    let fallback_src = format!(
        "/?full=1&enabled={spf_param}&provider={provider_param}{}{}",
        if published { "&published=1" } else { "" },
        if applied { "&notice=applied" } else { "" }
    );

    Ok(view! {
        <main class="mx-auto flex w-full max-w-3xl flex-col gap-6 px-4 py-10">
            <header class="flex flex-row items-start justify-between gap-4">
                <div class="flex flex-col gap-2">
                    <h1 class="text-2xl font-semibold tracking-tight">"SPF panel preview"</h1>
                    <p class="text-sm text-muted-foreground">
                        "The DNS record, previous addresses and public IPv4/IPv6 addresses are fixtures built through the library's core service and traits. No provider credentials, DNS records or public-address services are contacted."
                    </p>
                    <p class="text-sm text-muted-foreground">
                        "Simulate the saved DNS provider setting with the switch below."
                    </p>
                </div>
                button(
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::Icon,
                    attrs: attributes! {
                        id="theme-toggle"
                        type="button"
                        aria-label="Dark mode"
                        aria-pressed="true"
                        title="Switch to light mode"
                    },
                    icon(data: SUN, attrs: attributes! { class="hidden size-4 dark:block" })
                    icon(data: MOON, attrs: attributes! { class="size-4 dark:hidden" })
                )
            </header>

            <section
                class="flex flex-col gap-3 rounded-md border border-border p-4"
                aria-labelledby="preview-provider-heading"
            >
                <div class="flex flex-col gap-1">
                    <h2 id="preview-provider-heading" class="text-sm font-semibold">
                        "DNS provider (preview simulation)"
                    </h2>
                    <p class="text-xs text-muted-foreground">
                        "Preview only: this switch simulates the DNS provider's saved enabled setting. No provider credentials or DNS records are contacted. Turning it off also hides the fixture public addresses."
                    </p>
                </div>

                <form action="/provider" method="post" class="flex flex-col gap-3">
                    <div class="flex items-start gap-3">
                        switch(attrs: attributes! {
                            id="preview-provider-enabled"
                            name="provider"
                            value="true"
                            checked=(provider_enabled)
                            aria-describedby="preview-provider-description"
                            data-preview-provider=""
                        })
                        <div class="flex flex-col gap-1">
                            <label
                                class="text-sm leading-none font-medium select-none"
                                for="preview-provider-enabled"
                            >
                                "DNS provider enabled"
                            </label>
                            <p
                                id="preview-provider-description"
                                class="text-xs text-muted-foreground"
                            >
                                "Turning the provider off disables the SPF switch, Refresh and Publish. Turning it back on restores the independent SPF setting."
                            </p>
                        </div>
                    </div>
                    <input type="hidden" name="enabled" value=(spf_param)>
                    if published {
                        <input type="hidden" name="published" value="1">
                    }
                    if blocking {
                        <input type="hidden" name="full" value="1">
                    }
                    <noscript>
                        button(
                            variant: ButtonVariant::Secondary,
                            size: ButtonSize::Sm,
                            attrs: attributes! { type="submit" class="self-start" },
                            "Save provider state"
                        )
                    </noscript>
                </form>
            </section>

            if applied {
                alert(
                    variant: AlertVariant::Neutral,
                    alert_title("Preview only")
                    alert_description("The Publish action returned here without writing DNS or contacting a provider. The snapshot is rebuilt from the static DNS and public-address fixtures.")
                )
            }

            if let Some(contents) = contents {
                (contents)
            } else {
                <section
                    class="flex flex-col gap-3 rounded-md border border-border p-4"
                    data-spf-panel-region=""
                    data-spf-panel-src=(panel_src)
                    aria-busy="true"
                >
                    <div
                        class="flex items-start gap-3"
                        role="status"
                        aria-live="polite"
                        data-spf-loading=""
                    >
                        spinner(attrs: attributes! {
                            class="size-5 shrink-0 text-muted-foreground"
                            aria-hidden="true"
                        })
                        <div class="flex flex-col gap-1">
                            <p class="text-sm font-medium">
                                "Preparing the SPF panel…"
                            </p>
                            <p class="text-xs text-muted-foreground">
                                "The SPF record and actions will appear when the fixture inspection finishes."
                            </p>
                        </div>
                    </div>
                    <noscript>
                        <p class="text-sm text-muted-foreground">
                            "JavaScript is disabled, so the panel cannot load automatically. "
                            <a
                                class="font-medium text-foreground underline underline-offset-4"
                                href=(fallback_src.clone())
                            >
                                "Load the current record"
                            </a>
                            "."
                        </p>
                    </noscript>
                    <div hidden="" data-spf-load-error="" role="alert" class="flex flex-col gap-1">
                        <p class="text-sm font-medium">"Could not load the SPF panel."</p>
                        <p class="text-xs text-muted-foreground">
                            "Check the connection and "
                            <a
                                class="font-medium text-foreground underline underline-offset-4"
                                href=(fallback_src)
                            >
                                "load the current record"
                            </a>
                            "."
                        </p>
                    </div>
                </section>
            }
        </main>
    })
}

/// Returns the public-address notice and panel fragment used by the loading
/// shell. The request performs the same fixture inspection as the blocking
/// page, but only the fragment is sent back; the page shell is already visible.
#[route(GET "/panel")]
async fn panel_preview(cx: &Cx) -> Result<ViewHandle> {
    let query = query_params::<PreviewQuery>(cx)?;
    let spf_enabled = query.enabled.as_deref() != Some("0");
    let provider_enabled = query.provider.as_deref() != Some("0");
    let published = query.published.as_deref() == Some("1");
    let availability = preview_availability(spf_enabled, provider_enabled);
    let snapshot = if published {
        topcoat_spf::preview::published_snapshot(availability).await
    } else {
        topcoat_spf::preview::snapshot(availability).await
    };
    panel_contents(
        cx,
        &snapshot,
        if spf_enabled { "1" } else { "0" },
        if provider_enabled { "1" } else { "0" },
        published,
        false,
    )
    .await
}

/// The Publish form posts here. A successful simulated Publish redirects back
/// with the published fixture state, so the next panel reports Current and
/// Proposed as equal. Nothing is written to DNS.
#[route(POST "/apply")]
async fn apply_preview(cx: &Cx, Form(fields): Form<Vec<(String, String)>>) -> Result<SeeOther> {
    let spf_enabled = !contains(&fields, "enabled", "0");
    let provider_enabled = !contains(&fields, "provider", "0");
    let published = preview_availability(spf_enabled, provider_enabled).can_write();
    Ok(redirect_to_preview(
        &fields,
        spf_enabled,
        provider_enabled,
        published,
        true,
    ))
}

/// The Enable form posts here. The handler only redirects back with the
/// requested SPF preview state, so toggling the switch cannot mutate the DNS
/// provider setting or anything else. The provider preview state is preserved
/// from the form's hidden field.
#[route(POST "/enable")]
async fn enable_preview(cx: &Cx, Form(fields): Form<Vec<(String, String)>>) -> Result<SeeOther> {
    let spf_enabled = fields
        .iter()
        .any(|(name, value)| name == "enabled" && value == "true");
    let provider_enabled = !contains(&fields, "provider", "0");
    Ok(redirect_to_preview(
        &fields,
        spf_enabled,
        provider_enabled,
        contains(&fields, "published", "1"),
        false,
    ))
}

/// The preview-only DNS provider switch posts here. The handler only redirects
/// back with the simulated provider state and the SPF setting carried by the
/// hidden field, so toggling it cannot mutate anything.
#[route(POST "/provider")]
async fn provider_preview(cx: &Cx, Form(fields): Form<Vec<(String, String)>>) -> Result<SeeOther> {
    let provider_enabled = fields
        .iter()
        .any(|(name, value)| name == "provider" && value == "true");
    let spf_enabled = !contains(&fields, "enabled", "0");
    Ok(redirect_to_preview(
        &fields,
        spf_enabled,
        provider_enabled,
        contains(&fields, "published", "1"),
        false,
    ))
}

/// Keep the no-JavaScript full-page mode across form actions. The normal
/// asynchronous mode omits `full` so it keeps the fast shell.
fn redirect_to_preview(
    fields: &[(String, String)],
    spf_enabled: bool,
    provider_enabled: bool,
    published: bool,
    notice: bool,
) -> SeeOther {
    see_other(format!(
        "/?enabled={}&provider={}{}{}{}",
        if spf_enabled { "1" } else { "0" },
        if provider_enabled { "1" } else { "0" },
        if contains(fields, "full", "1") {
            "&full=1"
        } else {
            ""
        },
        if published { "&published=1" } else { "" },
        if notice { "&notice=applied" } else { "" },
    ))
}

fn contains(fields: &[(String, String)], name: &str, value: &str) -> bool {
    fields
        .iter()
        .any(|(field, field_value)| field == name && field_value == value)
}

fn router() -> Router {
    Router::builder()
        .layout(layout)
        .page(preview)
        .route(panel_preview)
        .route(apply_preview)
        .route(enable_preview)
        .route(provider_preview)
        .build()
}

/// Default listener when neither the environment nor `.env` sets one.
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 3000;

/// Listener settings file, searched for from the working directory upwards.
const ENV_FILE: &str = ".env";

/// Marker `topcoat dev` sets on the application process it starts.
const DEV_MARKER: &str = "TOPCOAT_DEV_URL";

/// The resolved preview listener.
#[derive(Debug, PartialEq, Eq)]
struct ListenerSettings {
    host: String,
    port: u16,
}

/// Serves the static preview on the configured host and port.
///
/// Process `HOST`/`PORT` values win, then the nearest `.env`, then
/// `127.0.0.1:3000`. `topcoat dev` cannot read `.env`: it resolves its own
/// `HOST`/`PORT` and injects them into this process. A value equal to its
/// built-in default is therefore treated as "not overridden" so the `.env`
/// listener still applies; any other value is an intentional override.
///
/// `topcoat::start` only reads the process environment, so the resolved
/// listener is bound here and passed to `topcoat::serve`, which still reports
/// readiness to `topcoat dev`.
pub async fn run() {
    let settings = match listener_settings() {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("topcoat-spf preview: {error}");
            std::process::exit(1);
        }
    };

    let listener = match TcpListener::bind((settings.host.as_str(), settings.port)).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "topcoat-spf preview: cannot bind {}:{}: {error}. \
                 Set HOST/PORT or update {ENV_FILE}.",
                settings.host, settings.port
            );
            std::process::exit(1);
        }
    };

    if let Err(error) = topcoat::serve(listener, router()).await {
        eprintln!("topcoat-spf preview: server error: {error}");
        std::process::exit(1);
    }
}

fn listener_settings() -> Result<ListenerSettings, io::Error> {
    resolve_listener(
        env::var_os(DEV_MARKER).is_some(),
        env_value("HOST")?,
        env_value("PORT")?,
        dotenv_value("HOST"),
        dotenv_value("PORT"),
    )
}

/// Resolves the listener from process values, `.env` values and defaults.
fn resolve_listener(
    under_dev: bool,
    process_host: Option<String>,
    process_port: Option<String>,
    dotenv_host: Option<String>,
    dotenv_port: Option<String>,
) -> Result<ListenerSettings, io::Error> {
    let host = select_listener_value(DEFAULT_HOST, under_dev, process_host, dotenv_host);
    let port = select_listener_value(
        &DEFAULT_PORT.to_string(),
        under_dev,
        process_port,
        dotenv_port,
    );

    Ok(ListenerSettings {
        host,
        port: parse_port("PORT", &port)?,
    })
}

/// Chooses one listener value.
///
/// A process value wins unless it is exactly the default that `topcoat dev`
/// injects when the user set nothing. In that case `.env` decides, because the
/// launcher itself never reads `.env`.
fn select_listener_value(
    default: &str,
    under_dev: bool,
    process_value: Option<String>,
    dotenv_value: Option<String>,
) -> String {
    match process_value {
        Some(value) if !under_dev || value != default => value,
        _ => dotenv_value.unwrap_or_else(|| default.to_owned()),
    }
}

fn env_value(name: &str) -> Result<Option<String>, io::Error> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be valid Unicode: {error}"),
        )),
    }
}

fn parse_port(name: &str, value: &str) -> Result<u16, io::Error> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a valid port number: {error}"),
        )
    })
}

/// Reads one entry from the nearest `.env`, if the file exists.
fn dotenv_value(name: &str) -> Option<String> {
    let mut dir = env::current_dir().ok()?;

    loop {
        if let Ok(contents) = fs::read_to_string(dir.join(ENV_FILE)) {
            return parse_dotenv(&contents, name);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn parse_dotenv(contents: &str, name: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let (key, value) = line.split_once('=')?;
        (key.trim() == name).then(|| unquote(value.trim()).to_owned())
    })
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    async fn start_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            topcoat::serve_until(listener, router(), std::future::pending::<()>())
                .await
                .expect("serve test router");
        });
        (addr, server)
    }

    async fn get(addr: SocketAddr, path: &str) -> (String, Duration) {
        let start = Instant::now();
        let mut stream = TcpStream::connect(addr).await.expect("connect test server");
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write test request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read test response");
        (
            String::from_utf8_lossy(&response).into_owned(),
            start.elapsed(),
        )
    }

    async fn post(addr: SocketAddr, path: &str, form: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect test server");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: text/html\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form}",
            form.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write test request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read test response");
        String::from_utf8_lossy(&response).into_owned()
    }

    fn location(response: &str) -> &str {
        response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("location").then(|| value.trim())
            })
            .expect("response has a Location header")
    }

    fn body(response: &str) -> &str {
        response
            .split_once("\r\n\r\n")
            .map_or(response, |(_, body)| body)
    }

    #[tokio::test]
    async fn initial_page_renders_a_loading_shell_without_waiting_for_the_panel() {
        let (addr, server) = start_server().await;
        let (response, elapsed) =
            tokio::time::timeout(Duration::from_secs(5), get(addr, "/?enabled=1&provider=1"))
                .await
                .expect("initial response is bounded");
        server.abort();

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            elapsed < Duration::from_secs(3),
            "initial page took {elapsed:?}"
        );

        let body = body(&response);
        assert!(body.contains("SPF panel preview"));
        assert!(body.contains("id=\"theme-toggle\""));
        assert!(body.contains("id=\"preview-provider-enabled\""));
        assert!(body.contains("data-spf-panel-region="));
        assert!(body.contains("data-spf-panel-src=\"/panel?enabled=1"));
        assert!(body.contains("data-spf-loading="));
        assert!(body.contains("animate-spin"));
        assert!(body.contains("role=\"status\""));
        assert!(body.contains("aria-busy=\"true\""));
        assert!(body.contains("Preparing the SPF panel"));
        assert!(body.contains("full=1"));
        assert!(body.contains("Load the current record"));
        assert!(
            !body.contains("data-spf-panel=\"\""),
            "the shell must not pretend the panel finished rendering"
        );
    }

    #[tokio::test]
    async fn simulated_publish_makes_current_and_proposed_equal() {
        let (addr, server) = start_server().await;

        let applied = tokio::time::timeout(
            Duration::from_secs(5),
            post(addr, "/apply", "enabled=1&provider=1"),
        )
        .await
        .expect("publish response is bounded");
        assert!(applied.starts_with("HTTP/1.1 303"), "{applied}");
        let location = location(&applied);
        assert!(location.contains("published=1"), "{location}");
        assert!(location.contains("notice=applied"), "{location}");

        let (shell, _) = tokio::time::timeout(
            Duration::from_secs(5),
            get(addr, "/?enabled=1&provider=1&published=1"),
        )
        .await
        .expect("published page is bounded");
        let shell_body = body(&shell);
        let panel_src = shell_body
            .split_once("data-spf-panel-src=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(src, _)| src)
            .expect("the loading shell points at the panel fragment");
        assert!(panel_src.contains("enabled=1"), "{panel_src}");
        assert!(panel_src.contains("provider=1"), "{panel_src}");
        assert!(panel_src.contains("published=1"), "{panel_src}");

        let (panel, _) = tokio::time::timeout(
            Duration::from_secs(5),
            get(addr, "/panel?enabled=1&provider=1&published=1"),
        )
        .await
        .expect("published panel is bounded");
        server.abort();

        assert!(panel.starts_with("HTTP/1.1 200"), "{panel}");
        let panel_body = body(&panel);
        assert!(panel_body.contains("data-spf-panel=\"\""));
        assert!(
            panel_body
                .contains("v=spf1 ip4:203.0.113.24 ip6:2001:db8::24 include:_spf.example.net -all"),
            "{panel_body}"
        );
        assert!(panel_body.contains("In sync"), "{panel_body}");
        assert!(
            !panel_body.contains(">Proposed"),
            "Proposed must be hidden after publishing: {panel_body}"
        );
        assert!(
            !panel_body.contains("id=\"desired-record\""),
            "{panel_body}"
        );
    }

    #[tokio::test]
    async fn disabled_page_and_fragment_skip_address_inspection() {
        let (addr, server) = start_server().await;

        let (page, elapsed) =
            tokio::time::timeout(Duration::from_secs(5), get(addr, "/?enabled=0&provider=1"))
                .await
                .expect("disabled page is bounded");
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(
            elapsed < Duration::from_secs(3),
            "disabled page took {elapsed:?}"
        );
        let page_body = body(&page);
        assert!(page_body.contains("data-spf-panel=\"\""));
        assert!(page_body.contains("Enable to refresh or publish"));
        assert!(page_body.contains("skipped"));
        assert!(!page_body.contains("data-spf-loading="));

        let (fragment, elapsed) = tokio::time::timeout(
            Duration::from_secs(5),
            get(addr, "/panel?enabled=0&provider=1"),
        )
        .await
        .expect("panel fragment is bounded");
        server.abort();

        assert!(fragment.starts_with("HTTP/1.1 200"), "{fragment}");
        assert!(
            elapsed < Duration::from_secs(3),
            "panel fragment took {elapsed:?}"
        );
        let fragment_body = body(&fragment);
        assert!(fragment_body.contains("data-spf-panel=\"\""));
        assert!(fragment_body.contains("Enable to refresh or publish"));
        assert!(!fragment_body.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn dotenv_entries_ignore_comments_and_trim_values() {
        let contents = "# listener\nHOST = 0.0.0.0\nPORT=8080\n";
        assert_eq!(parse_dotenv(contents, "HOST").as_deref(), Some("0.0.0.0"));
        assert_eq!(parse_dotenv(contents, "PORT").as_deref(), Some("8080"));
        assert_eq!(parse_dotenv(contents, "MISSING"), None);
    }

    #[test]
    fn dotenv_values_accept_matching_quotes() {
        assert_eq!(
            parse_dotenv("HOST=\"0.0.0.0\"\n", "HOST").as_deref(),
            Some("0.0.0.0")
        );
        assert_eq!(
            parse_dotenv("HOST='127.0.0.1'\n", "HOST").as_deref(),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn dotenv_values_handle_crlf_line_endings() {
        assert_eq!(
            parse_dotenv("HOST=127.0.0.1\r\nPORT=13003\r\n", "PORT").as_deref(),
            Some("13003")
        );
    }

    #[test]
    fn listener_defaults_when_nothing_is_configured() {
        assert_eq!(
            resolve_listener(false, None, None, None, None).unwrap(),
            ListenerSettings {
                host: "127.0.0.1".to_owned(),
                port: 3000,
            }
        );
    }

    #[test]
    fn process_values_override_dotenv_outside_dev() {
        assert_eq!(
            resolve_listener(
                false,
                Some("0.0.0.0".to_owned()),
                Some("8080".to_owned()),
                Some("127.0.0.1".to_owned()),
                Some("13003".to_owned()),
            )
            .unwrap(),
            ListenerSettings {
                host: "0.0.0.0".to_owned(),
                port: 8080,
            }
        );
    }

    #[test]
    fn dotenv_values_fill_in_missing_process_values() {
        assert_eq!(
            resolve_listener(
                false,
                None,
                None,
                Some("0.0.0.0".to_owned()),
                Some("13003".to_owned()),
            )
            .unwrap(),
            ListenerSettings {
                host: "0.0.0.0".to_owned(),
                port: 13003,
            }
        );
    }

    #[test]
    fn dev_defaults_let_dotenv_choose_the_listener() {
        assert_eq!(
            resolve_listener(
                true,
                Some("127.0.0.1".to_owned()),
                Some("3000".to_owned()),
                Some("0.0.0.0".to_owned()),
                Some("13003".to_owned()),
            )
            .unwrap(),
            ListenerSettings {
                host: "0.0.0.0".to_owned(),
                port: 13003,
            }
        );
    }

    #[test]
    fn dev_non_default_overrides_win_over_dotenv() {
        assert_eq!(
            resolve_listener(
                true,
                Some("0.0.0.0".to_owned()),
                Some("8080".to_owned()),
                Some("127.0.0.1".to_owned()),
                Some("13003".to_owned()),
            )
            .unwrap(),
            ListenerSettings {
                host: "0.0.0.0".to_owned(),
                port: 8080,
            }
        );
    }

    #[test]
    fn invalid_ports_are_rejected() {
        assert!(resolve_listener(false, None, Some("nope".to_owned()), None, None).is_err());
        assert!(resolve_listener(false, None, None, None, Some("70000".to_owned())).is_err());
    }
}
