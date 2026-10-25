/**
 * PhishLens Theme Manager
 * Manages Dark/Light modes with system preference detection and localStorage persistence.
 */

const STORAGE_KEY = "phishlens_theme";

class ThemeManager {
  constructor() {
    this._mediaQuery = window.matchMedia("(prefers-color-scheme: light)");
    this._theme = this._resolveInitialTheme();
  }

  get currentTheme() {
    return this._theme;
  }

  get isLight() {
    return this._theme === "light";
  }

  _resolveInitialTheme() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") {
      return saved;
    }
    return this._mediaQuery.matches ? "light" : "dark";
  }

  init() {
    this.applyTheme(this._theme, false);

    // Watch for OS preference changes if user hasn't explicitly set a preference
    this._mediaQuery.addEventListener("change", (e) => {
      if (!localStorage.getItem(STORAGE_KEY)) {
        this.applyTheme(e.matches ? "light" : "dark", false);
      }
    });

    // Wire up theme toggle buttons
    const toggleButtons = document.querySelectorAll("[data-theme-toggle]");
    toggleButtons.forEach((btn) => {
      btn.addEventListener("click", () => this.toggle());
      this._updateButtonAria(btn);
    });
  }

  applyTheme(theme, persist = true) {
    this._theme = theme;
    document.documentElement.setAttribute("data-theme", theme);

    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, theme);
      } catch (err) {
        console.warn("[PhishLens] Could not save theme preference:", err);
      }
    }

    const toggleButtons = document.querySelectorAll("[data-theme-toggle]");
    toggleButtons.forEach((btn) => this._updateButtonAria(btn));

    // Dispatch custom event for Leaflet map tiles & SVG meters
    window.dispatchEvent(
      new CustomEvent("phishlens:theme-change", { detail: { theme } })
    );
  }

  toggle() {
    const next = this._theme === "light" ? "dark" : "light";
    this.applyTheme(next, true);
  }

  _updateButtonAria(btn) {
    const isLight = this._theme === "light";
    btn.setAttribute("aria-label", isLight ? "Switch to dark mode" : "Switch to light mode");
    btn.setAttribute("title", isLight ? "Switch to dark mode" : "Switch to light mode");
  }
}

export const themeManager = new ThemeManager();

// Auto-initialize when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => themeManager.init());
} else {
  themeManager.init();
}
