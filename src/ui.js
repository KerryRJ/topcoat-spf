// Include once on pages that render spf_panel. Event delegation also handles
// panels added or replaced after the initial page load.
(() => {
  const sync = (input) => {
    const panel = input.closest("[data-spf-panel]");
    if (!panel) return;
    for (const control of panel.querySelectorAll("[data-spf-control]")) {
      // Restore the server-rendered state, which also accounts for busy,
      // availability policy and whether an update is needed.
      control.disabled = !input.checked || control.hasAttribute("data-spf-disabled");
    }
  };

  document.addEventListener("change", (event) => {
    const input = event.target.closest("[data-spf-enabled]");
    if (!input) return;
    const panel = input.closest("[data-spf-panel]");
    // An action navigation is already in flight; do not start another request.
    if (panel?.dataset.spfSubmitting) return;
    sync(input);
    input.form?.requestSubmit();
  });

  const setLoading = (panel, button) => {
    const label = button.dataset.spfBusyLabel || "Working…";
    panel.dataset.spfSubmitting = button.dataset.spfAction || "action";
    panel.setAttribute("aria-busy", "true");

    for (const control of panel.querySelectorAll("[data-spf-action]")) {
      // Dim the other action without disabling any form field. The submitting
      // form still carries every field when it navigates, and its spinner stays
      // at full contrast.
      if (control === button) {
        control.removeAttribute("aria-disabled");
      } else {
        control.setAttribute("aria-disabled", "true");
      }
      control
        .querySelector("[data-spf-icon]")
        ?.classList.toggle("hidden", control === button);
      control
        .querySelector("[data-spf-spinner]")
        ?.classList.toggle("hidden", control !== button);
      if (control === button) {
        const text = control.querySelector("[data-spf-label]");
        if (text) text.textContent = label;
      }
    }

    for (const input of panel.querySelectorAll("[data-spf-enabled]")) {
      input.setAttribute("aria-disabled", "true");
    }

    const status = panel.querySelector("[data-spf-status]");
    if (status) status.textContent = label;
  };

  document.addEventListener("submit", (event) => {
    if (event.defaultPrevented) return;
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const panel = form.closest("[data-spf-panel]");
    if (!panel) return;

    // A native navigation is already in flight. Block repeat clicks, the
    // Enable switch and overlapping Refresh/Publish submissions without
    // touching form data.
    if (panel.dataset.spfSubmitting) {
      event.preventDefault();
      return;
    }

    const button = form.querySelector("[data-spf-action]");
    if (!button) return;
    setLoading(panel, button);
  });

  const restore = (panel) => {
    delete panel.dataset.spfSubmitting;
    panel.setAttribute("aria-busy", "false");

    for (const control of panel.querySelectorAll("[data-spf-action]")) {
      control.removeAttribute("aria-disabled");
      control.querySelector("[data-spf-icon]")?.classList.remove("hidden");
      control.querySelector("[data-spf-spinner]")?.classList.add("hidden");
      const text = control.querySelector("[data-spf-label]");
      const idle = control.dataset.spfIdleLabel;
      if (text && idle) text.textContent = idle;
    }

    for (const input of panel.querySelectorAll("[data-spf-enabled]")) {
      input.removeAttribute("aria-disabled");
    }

    const status = panel.querySelector("[data-spf-status]");
    if (status) status.textContent = "";
  };

  // Restored pages, including bfcache back/forward navigation, must not keep
  // showing a progress state for a request that is no longer in flight.
  window.addEventListener("pageshow", () => {
    for (const panel of document.querySelectorAll(
      "[data-spf-panel][data-spf-submitting]",
    )) {
      restore(panel);
    }
  });

  const initialize = () => {
    for (const input of document.querySelectorAll("[data-spf-enabled]")) sync(input);
  };

  // A host can load a panel after the initial page render. Re-run the
  // server-state synchronization once the new markup is in the document.
  document.addEventListener("spf:panel-loaded", initialize);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize);
  } else {
    initialize();
  }
})();
