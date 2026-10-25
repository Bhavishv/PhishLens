/**
 * PhishLens Security & Defanging Utilities
 * Prevents execution of hostile URLs, domains, and email addresses by converting them
 * into non-clickable, neutral text (e.g. hxxps://evil[.]com, admin[at]domain[.]com).
 * Also provides safe DOM construction to eliminate unsafe innerHTML calls.
 */

/**
 * Defang a URL so it cannot be clicked or auto-linked by browsers.
 * Replaces http(s) with hxxp(s), and dots in domain with [.]
 * Example: "https://evil.com/login" -> "hxxps://evil[.]com/login"
 */
export function defangUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return "";

  let defanged = rawUrl.trim();

  // Protocol defanging
  defanged = defanged.replace(/^https:\/\//i, "hxxps://");
  defanged = defanged.replace(/^http:\/\//i, "hxxp://");

  // Extract host portion if scheme was present
  try {
    const urlObj = new URL(rawUrl.startsWith("http") ? rawUrl : `http://${rawUrl}`);
    const originalHost = urlObj.hostname;
    const defangedHost = defangDomain(originalHost);

    // Replace the first occurrence of the host in the defanged string
    defanged = defanged.replace(originalHost, defangedHost);
  } catch {
    // If URL parsing fails, perform simple global dot replacement before first slash
    const slashIdx = defanged.indexOf("/", 8);
    if (slashIdx !== -1) {
      const hostPart = defanged.slice(0, slashIdx).replace(/\./g, "[.]");
      defanged = hostPart + defanged.slice(slashIdx);
    } else {
      defanged = defanged.replace(/\./g, "[.]");
    }
  }

  // Defang '@' signs in URLs (often used in credential spoofing)
  return defanged.replace(/@/g, "[at]");
}

/**
 * Defang a domain name or IP address.
 * Example: "paypal.com" -> "paypal[.]com", "203.0.113.45" -> "203.0.113[.]45"
 */
export function defangDomain(rawDomain) {
  if (!rawDomain || typeof rawDomain !== "string") return "";
  const trimmed = rawDomain.trim();
  // Replace the last dot or all dots
  return trimmed.replace(/\./g, "[.]");
}

/**
 * Defang an email address.
 * Example: "phisher@evil.com" -> "phisher[at]evil[.]com"
 */
export function defangEmail(rawEmail) {
  if (!rawEmail || typeof rawEmail !== "string") return "";
  return rawEmail
    .trim()
    .replace(/@/g, "[at]")
    .replace(/\./g, "[.]");
}

/**
 * Safe HTML string escaper.
 */
export function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Safe DOM Element Factory.
 * Builds DOM elements using pure properties (textContent, setAttribute)
 * to strictly prevent XSS from hostile email content.
 */
export function createSafeElement(tag, options = {}) {
  const el = document.createElement(tag);

  if (options.className) {
    el.className = options.className;
  }

  if (options.text !== undefined && options.text !== null) {
    el.textContent = String(options.text);
  }

  if (options.attributes) {
    for (const [key, val] of Object.entries(options.attributes)) {
      if (val !== null && val !== undefined) {
        el.setAttribute(key, String(val));
      }
    }
  }

  if (options.children && Array.isArray(options.children)) {
    for (const child of options.children) {
      if (child instanceof Node) {
        el.appendChild(child);
      } else if (typeof child === "string") {
        el.appendChild(document.createTextNode(child));
      }
    }
  }

  return el;
}
