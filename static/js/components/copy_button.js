/**
 * PhishLens Accessible Copy Button Component
 * Copies text to clipboard, provides visual feedback, and makes screen-reader
 * announcements using an aria-live region.
 */

const CHECK_ICON_SVG = `
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <polyline points="20 6 9 17 4 12"></polyline>
</svg>
`;

const COPY_ICON_SVG = `
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
</svg>
`;

/**
 * Screen reader announcer using aria-live polite region.
 */
export function announceScreenReader(message) {
  let announcer = document.getElementById("a11yAnnouncer");
  if (!announcer) {
    announcer = document.createElement("div");
    announcer.id = "a11yAnnouncer";
    announcer.className = "sr-only";
    announcer.setAttribute("role", "status");
    announcer.setAttribute("aria-live", "polite");
    announcer.setAttribute("aria-atomic", "true");
    document.body.appendChild(announcer);
  }

  // Clear and update to re-trigger announcement
  announcer.textContent = "";
  setTimeout(() => {
    announcer.textContent = message;
  }, 50);
}

export async function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
  } else {
    // Fallback for non-https or older browsers
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-999999px";
    textarea.style.top = "-999999px";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
}

export function initCopyButtons(container = document) {
  const buttons = container.querySelectorAll("[data-copy-btn]");
  buttons.forEach((btn) => {
    if (btn._copyBound) return;
    btn._copyBound = true;

    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      let textToCopy = btn.getAttribute("data-copy-text");

      if (!textToCopy) {
        const targetSelector = btn.getAttribute("data-copy-target");
        if (targetSelector) {
          const targetEl = document.querySelector(targetSelector);
          if (targetEl) textToCopy = targetEl.textContent.trim();
        }
      }

      if (!textToCopy) return;

      try {
        await copyToClipboard(textToCopy);
        const originalHtml = btn.innerHTML;
        const originalLabel = btn.getAttribute("aria-label") || "Copy to clipboard";

        btn.innerHTML = CHECK_ICON_SVG;
        btn.classList.add("copied");
        btn.setAttribute("aria-label", "Copied to clipboard");
        announceScreenReader("Copied to clipboard");

        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.classList.remove("copied");
          btn.setAttribute("aria-label", originalLabel);
        }, 2000);
      } catch (err) {
        console.error("[PhishLens] Clipboard copy failed:", err);
        announceScreenReader("Failed to copy to clipboard");
      }
    });
  });
}

// Auto-initialize copy buttons on page load
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => initCopyButtons());
} else {
  initCopyButtons();
}
