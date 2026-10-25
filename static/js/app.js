/**
 * PhishLens Application Controller
 * Handles file drag-and-drop, client-side validation, raw header input,
 * staged loading indicators, demo sample loading, and analysis orchestration.
 */

import { config } from "./config.js";
import { labels } from "./labels.js";
import { api } from "./api.js";
import { createSafeElement } from "./defang.js";

class AppController {
  constructor() {
    this._selectedFile = null;
    this._activeTab = "upload";
    this._lastAnalysisResult = null;
  }

  async init() {
    // 1. Initialize backend config
    await config.init();

    // 2. Cache DOM elements
    this.tabUpload = document.getElementById("tabUploadBtn");
    this.tabPaste = document.getElementById("tabPasteBtn");
    this.panelUpload = document.getElementById("panelUpload");
    this.panelPaste = document.getElementById("panelPaste");

    this.dropzone = document.getElementById("dropzone");
    this.fileInput = document.getElementById("fileInput");
    this.fileChip = document.getElementById("fileChip");
    this.fileNameEl = document.getElementById("fileName");
    this.fileSizeEl = document.getElementById("fileSize");
    this.removeFileBtn = document.getElementById("removeFileBtn");

    this.rawTextarea = document.getElementById("rawTextarea");
    this.charCountEl = document.getElementById("charCount");
    this.clearRawBtn = document.getElementById("clearRawBtn");

    this.analyzeBtn = document.getElementById("analyzeBtn");
    this.maskToggle = document.getElementById("maskDataToggle");
    this.alertContainer = document.getElementById("alertContainer");

    this.progressCard = document.getElementById("progressCard");
    this.progressStageEl = document.getElementById("progressStageText");
    this.progressBarFill = document.getElementById("progressBarFill");

    this.sampleLegitBtn = document.getElementById("sampleLegitBtn");
    this.samplePhishBtn = document.getElementById("samplePhishBtn");

    this.resultsContainer = document.getElementById("resultsContainer");

    // 3. Bind UI event listeners
    this._bindTabs();
    this._bindDropzone();
    this._bindRawInput();
    this._bindAnalyze();
    this._bindSampleButtons();
  }

  /* -------------------------------------------------------------------------
   * Tab Switching Logic
   * ------------------------------------------------------------------------- */
  _bindTabs() {
    if (!this.tabUpload || !this.tabPaste) return;

    this.tabUpload.addEventListener("click", () => this._switchTab("upload"));
    this.tabPaste.addEventListener("click", () => this._switchTab("paste"));
  }

  _switchTab(tab) {
    this._activeTab = tab;
    const isUpload = tab === "upload";

    this.tabUpload.setAttribute("aria-selected", isUpload ? "true" : "false");
    this.tabPaste.setAttribute("aria-selected", isUpload ? "false" : "true");

    this.panelUpload.style.display = isUpload ? "block" : "none";
    this.panelPaste.style.display = isUpload ? "none" : "block";

    this._clearAlerts();
  }

  /* -------------------------------------------------------------------------
   * File Drag & Drop + Browse
   * ------------------------------------------------------------------------- */
  _bindDropzone() {
    if (!this.dropzone || !this.fileInput) return;

    // Click on dropzone triggers file picker
    this.dropzone.addEventListener("click", () => this.fileInput.click());

    // Keyboard access (Enter / Space)
    this.dropzone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        this.fileInput.click();
      }
    });

    this.fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        this._handleSelectedFile(e.target.files[0]);
      }
    });

    // Drag-and-drop events
    const highlight = (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.dropzone.classList.add("dragover");
    };

    const unhighlight = (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.dropzone.classList.remove("dragover");
    };

    ["dragenter", "dragover"].forEach((evt) => {
      this.dropzone.addEventListener(evt, highlight, false);
    });

    ["dragleave", "drop"].forEach((evt) => {
      this.dropzone.addEventListener(evt, unhighlight, false);
    });

    this.dropzone.addEventListener("drop", (e) => {
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        this._handleSelectedFile(dt.files[0]);
      }
    });

    if (this.removeFileBtn) {
      this.removeFileBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this._clearSelectedFile();
      });
    }
  }

  _handleSelectedFile(file) {
    this._clearAlerts();

    // 1. Validate file extension
    const ext = `.${file.name.split(".").pop().toLowerCase()}`;
    const allowed = config.allowedExtensions;
    if (!allowed.includes(ext)) {
      this._showAlert(labels.errors.invalidFileType, "danger");
      return;
    }

    // 2. Validate file size
    if (file.size > config.maxEmailSizeBytes) {
      const maxMb = Math.round(config.maxEmailSizeBytes / (1024 * 1024));
      this._showAlert(labels.errors.fileTooLarge.replace("{maxSize}", `${maxMb} MB`), "danger");
      return;
    }

    // 3. Validate non-empty
    if (file.size === 0) {
      this._showAlert(labels.errors.emptyFile, "danger");
      return;
    }

    this._selectedFile = file;

    // Update UI chip
    if (this.fileNameEl) this.fileNameEl.textContent = file.name;
    if (this.fileSizeEl) this.fileSizeEl.textContent = this._formatBytes(file.size);
    if (this.fileChip) this.fileChip.style.display = "flex";
  }

  _clearSelectedFile() {
    this._selectedFile = null;
    if (this.fileInput) this.fileInput.value = "";
    if (this.fileChip) this.fileChip.style.display = "none";
  }

  /* -------------------------------------------------------------------------
   * Raw Header Textarea Input
   * ------------------------------------------------------------------------- */
  _bindRawInput() {
    if (!this.rawTextarea) return;

    this.rawTextarea.addEventListener("input", () => {
      const len = this.rawTextarea.value.length;
      if (this.charCountEl) {
        this.charCountEl.textContent = labels.paste.charCount.replace("{count}", len.toLocaleString());
      }
    });

    if (this.clearRawBtn) {
      this.clearRawBtn.addEventListener("click", () => {
        this.rawTextarea.value = "";
        this.rawTextarea.dispatchEvent(new Event("input"));
      });
    }
  }

  /* -------------------------------------------------------------------------
   * Sample Email Quick Loader (Demo Mode)
   * ------------------------------------------------------------------------- */
  _bindSampleButtons() {
    if (this.sampleLegitBtn) {
      this.sampleLegitBtn.addEventListener("click", () => this._loadSample("legit"));
    }
    if (this.samplePhishBtn) {
      this.samplePhishBtn.addEventListener("click", () => this._loadSample("phishing"));
    }
  }

  async _loadSample(sampleName) {
    this._clearAlerts();
    this._switchTab("paste");
    if (this.rawTextarea) {
      this.rawTextarea.value = "Loading sample email headers...";
    }

    const res = await api.fetchSample(sampleName);
    if (res.ok && this.rawTextarea) {
      this.rawTextarea.value = res.text;
      this.rawTextarea.dispatchEvent(new Event("input"));
      this._showAlert(`Loaded ${sampleName === "phishing" ? "phishing" : "legitimate"} sample email. Click 'Analyze Email' to scan.`, "info");
    } else {
      this._showAlert(res.error || "Failed to load sample", "danger");
    }
  }

  /* -------------------------------------------------------------------------
   * Analysis Execution & State Management
   * ------------------------------------------------------------------------- */
  _bindAnalyze() {
    if (!this.analyzeBtn) return;

    this.analyzeBtn.addEventListener("click", async () => {
      this._clearAlerts();

      const isUpload = this._activeTab === "upload";
      const file = isUpload ? this._selectedFile : null;
      const rawText = !isUpload && this.rawTextarea ? this.rawTextarea.value : null;

      if (!file && (!rawText || !rawText.trim())) {
        this._showAlert(labels.errors.noInput, "warning");
        return;
      }

      const maskPersonalData = Boolean(this.maskToggle && this.maskToggle.checked);

      // Start loading state
      this._setLoadingState(true);

      const totalStages = labels.progressStages.length;
      const res = await api.analyze({
        file,
        rawText,
        maskPersonalData,
        onProgress: (stageText, stepIndex) => {
          if (this.progressStageEl) this.progressStageEl.textContent = stageText;
          if (this.progressBarFill) {
            const pct = Math.min(Math.round(((stepIndex + 1) / totalStages) * 100), 100);
            this.progressBarFill.style.width = `${pct}%`;
          }
        },
      });

      this._setLoadingState(false);

      if (!res.ok) {
        this._showAlert(res.error, "danger");
        return;
      }

      this._lastAnalysisResult = res.data;

      // Broadcast analysis result for Task 3 results dashboard
      window.dispatchEvent(
        new CustomEvent("phishlens:analysis-complete", { detail: res.data })
      );

      // Render preliminary success summary banner & scroll
      this._renderSuccessSummary(res.data);
    });
  }

  _setLoadingState(isLoading) {
    if (this.analyzeBtn) {
      this.analyzeBtn.disabled = isLoading;
      this.analyzeBtn.textContent = isLoading ? labels.upload.scanningButton : labels.upload.scanButton;
    }

    if (this.progressCard) {
      this.progressCard.style.display = isLoading ? "block" : "none";
      if (isLoading && this.progressBarFill) {
        this.progressBarFill.style.width = "10%";
      }
    }
  }

  /* -------------------------------------------------------------------------
   * Alerts & Notifications
   * ------------------------------------------------------------------------- */
  _showAlert(message, type = "info") {
    if (!this.alertContainer) return;
    this._clearAlerts();

    const alertEl = createSafeElement("div", {
      className: `alert alert-${type}`,
      attributes: { role: "alert", "aria-live": "polite" },
      children: [
        createSafeElement("div", { text: message }),
      ],
    });

    this.alertContainer.appendChild(alertEl);
    alertEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  _clearAlerts() {
    if (this.alertContainer) {
      this.alertContainer.innerHTML = "";
    }
  }

  _formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }

  /* -------------------------------------------------------------------------
   * Preliminary Result Card (Task 2 handoff to Task 3)
   * ------------------------------------------------------------------------- */
  _renderSuccessSummary(data) {
    if (!this.resultsContainer) return;

    this.resultsContainer.innerHTML = "";
    const risk = data.risk || {};
    const meta = data.email_metadata || {};
    const badgeClass = `badge-${(risk.label || "low").toLowerCase().replace(" risk", "").replace(" ", "-")}`;

    const card = createSafeElement("div", {
      className: "card card-elevated",
      children: [
        createSafeElement("div", {
          className: "card-header",
          children: [
            createSafeElement("span", {
              className: `badge ${badgeClass}`,
              text: `${risk.label || "Verdict"} (${risk.score || 0}/100)`,
            }),
            createSafeElement("span", {
              className: "text-muted",
              text: `SHA-256: ${(data.file_sha256 || "").slice(0, 16)}...`,
            }),
          ],
        }),
        createSafeElement("p", {
          text: `Subject: ${meta.subject || "(No subject)"}`,
        }),
        createSafeElement("p", {
          className: "text-muted",
          text: `From: ${meta.from || "(Unknown sender)"}`,
        }),
        createSafeElement("div", {
          className: "alert alert-info",
          text: `Analysis complete! Evaluated ${data.origin?.total_hops || 0} relay hops and ${(data.url_analysis?.url_findings || []).length} URLs. Forensic dashboard ready.`,
        }),
      ],
    });

    this.resultsContainer.appendChild(card);
    this.resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

export const app = new AppController();

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => app.init());
} else {
  app.init();
}
