/**
 * PhishLens API Client
 * Robust asynchronous fetch wrapper with staged progress callbacks, timeouts,
 * and normalized error reporting.
 */

import { config } from "./config.js";
import { labels } from "./labels.js";

const DEFAULT_TIMEOUT_MS = 45000; // 45 seconds timeout for deep DNS/WHOIS queries

export class ApiClient {
  /**
   * Run the analysis pipeline on an email file or raw text.
   *
   * @param {Object} options
   * @param {File|null} options.file - Uploaded .eml File object
   * @param {string|null} options.rawText - Raw header / email text
   * @param {boolean} options.maskPersonalData - Whether to mask PII
   * @param {function} [options.onProgress] - Callback (stageText, stepIndex)
   * @returns {Promise<{ok: boolean, data?: Object, error?: string, status?: number}>}
   */
  async analyze({ file = null, rawText = null, maskPersonalData = false, onProgress = null }) {
    if (!file && (!rawText || !rawText.trim())) {
      return { ok: false, error: labels.errors.noInput, status: 400 };
    }

    const formData = new FormData();
    if (file) {
      formData.append("file", file, file.name);
    } else {
      formData.append("raw", rawText.trim());
    }

    if (maskPersonalData) {
      formData.append("mask_personal_data", "1");
    }

    // Set up staged progress timer
    let progressTimer = null;
    let currentStage = 0;
    const stages = labels.progressStages;

    if (typeof onProgress === "function") {
      onProgress(stages[0], 0);
      progressTimer = setInterval(() => {
        if (currentStage < stages.length - 1) {
          currentStage += 1;
          onProgress(stages[currentStage], currentStage);
        }
      }, 500);
    }

    // Set up abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

    try {
      const response = await fetch(config.endpoints.analyze, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      if (progressTimer) clearInterval(progressTimer);

      const contentType = response.headers.get("content-type") || "";
      let payload = null;

      if (contentType.includes("application/json")) {
        payload = await response.json();
      } else {
        const text = await response.text();
        payload = { error: text || `HTTP ${response.status}` };
      }

      if (!response.ok) {
        let errorMsg = payload?.error || labels.errors.serverError;
        if (response.status === 413) {
          errorMsg = labels.errors.fileTooLarge.replace("{maxSize}", "25 MB");
        } else if (response.status === 400 && !payload?.error) {
          errorMsg = labels.errors.invalidFileType;
        }
        return { ok: false, error: errorMsg, status: response.status };
      }

      // Final progress tick
      if (typeof onProgress === "function") {
        onProgress(stages[stages.length - 1], stages.length - 1);
      }

      return { ok: true, data: payload, status: response.status };
    } catch (err) {
      clearTimeout(timeoutId);
      if (progressTimer) clearInterval(progressTimer);

      if (err.name === "AbortError") {
        return { ok: false, error: labels.errors.timeout, status: 408 };
      }
      return { ok: false, error: labels.errors.networkError, status: 0 };
    }
  }

  /**
   * Fetch sample email content for the demo workflow.
   *
   * @param {"legit"|"phishing"} sampleName
   * @returns {Promise<{ok: boolean, text?: string, error?: string}>}
   */
  async fetchSample(sampleName) {
    try {
      const response = await fetch(`/sample/${encodeURIComponent(sampleName)}`);
      if (!response.ok) {
        return { ok: false, error: `Could not load sample '${sampleName}' (HTTP ${response.status})` };
      }
      const text = await response.text();
      return { ok: true, text };
    } catch (err) {
      return { ok: false, error: `Network error loading sample: ${err.message}` };
    }
  }
}

export const api = new ApiClient();
