/**
 * PhishLens Client Configuration
 * Single source of truth for API endpoints, timeouts, and backend metadata.
 */

const DEFAULT_META = {
  app_name: "PhishLens",
  app_version: "1.0.0",
  max_email_size_bytes: 25 * 1024 * 1024, // 25 MB
  allowed_extensions: [".eml"],
  thresholds: {
    low: 29,
    suspicious: 59,
    high: 79,
  },
  weights: {
    authentication: 25,
    header_anomalies: 20,
    content_ml: 25,
    urls: 15,
    sender_domain: 15,
  },
};

class ConfigManager {
  constructor() {
    this._meta = { ...DEFAULT_META };
    this._initialized = false;
  }

  get endpoints() {
    return {
      meta: "/meta",
      analyze: "/analyze",
      results: (id) => `/results/${encodeURIComponent(id)}`,
      report: (id) => `/report/${encodeURIComponent(id)}`,
      health: "/health",
    };
  }

  get meta() {
    return this._meta;
  }

  get maxEmailSizeBytes() {
    return this._meta.max_email_size_bytes;
  }

  get allowedExtensions() {
    return this._meta.allowed_extensions;
  }

  get thresholds() {
    return this._meta.thresholds;
  }

  get weights() {
    return this._meta.weights;
  }

  get appVersion() {
    return this._meta.app_version;
  }

  /**
   * Fetch live metadata from backend `/meta` endpoint.
   * Gracefully falls back to default constants if offline or unavailable.
   */
  async init() {
    if (this._initialized) return this._meta;
    try {
      const response = await fetch(this.endpoints.meta, {
        headers: { Accept: "application/json" },
      });
      if (response.ok) {
        const remoteMeta = await response.json();
        this._meta = { ...this._meta, ...remoteMeta };
      }
    } catch (err) {
      console.warn("[PhishLens] Could not fetch /meta, using fallback constants:", err);
    }
    this._initialized = true;
    return this._meta;
  }
}

export const config = new ConfigManager();
