/**
 * PhishLens Accessible Copy Button Component
 * Copies text to clipboard and provides visual & screen-reader confirmation.
 */

const CHECK_ICON_SVG = `
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
  <polyline points="20 6 9 17 4 12"></polyline>
</svg>
`;

const COPY_ICON_SVG = `
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
</svg>
`;

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
    // Avoid double binding
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
        btn.innerHTML = CHECK_ICON_SVG;
        btn.classList.add("copied");
        btn.setAttribute("aria-label", "Copied to clipboard");

        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.classList.remove("copied");
          btn.setAttribute("aria-label", "Copy to clipboard");
        }, 2000);
      } catch (err) {
        console.error("[PhishLens] Clipboard copy failed:", err);
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
