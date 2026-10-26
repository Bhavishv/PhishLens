/**
 * PhishLens Application Controller
 * Handles file drag-and-drop, client-side validation, raw header input,
 * staged loading indicators, demo sample loading, and full forensic results rendering.
 */

import { config } from "./config.js";
import { labels } from "./labels.js";
import { api } from "./api.js";
import { createSafeElement, defangUrl, defangDomain, defangEmail } from "./defang.js";
import { renderRiskGauge } from "./components/gauge.js";
import { renderWhyWeThinkSo } from "./components/reasons.js";
import { renderOriginSection } from "./components/map.js";
import { renderLinksAndAttachments } from "./components/links.js";
import { renderAnalystDrawer } from "./components/analyst_drawer.js";
import { initCopyButtons, announceScreenReader } from "./components/copy_button.js";

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

    this.dropzone.addEventListener("click", () => this.fileInput.click());

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

    const ext = `.${file.name.split(".").pop().toLowerCase()}`;
    const allowed = config.allowedExtensions;
    if (!allowed.includes(ext)) {
      this._showAlert(labels.errors.invalidFileType, "danger");
      return;
    }

    if (file.size > config.maxEmailSizeBytes) {
      const maxMb = Math.round(config.maxEmailSizeBytes / (1024 * 1024));
      this._showAlert(labels.errors.fileTooLarge.replace("{maxSize}", `${maxMb} MB`), "danger");
      return;
    }

    if (file.size === 0) {
      this._showAlert(labels.errors.emptyFile, "danger");
      return;
    }

    this._selectedFile = file;

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
      this._showAlert(`Loaded ${sampleName === "phishing" ? "scam email example" : "clean email example"}. Click 'Check Email Safety' to see the results.`, "info");
      if (this.analyzeBtn) {
        this.analyzeBtn.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
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

      // Broadcast analysis result
      window.dispatchEvent(
        new CustomEvent("phishlens:analysis-complete", { detail: res.data })
      );

      // Render the complete Task 3 forensic results dashboard
      this._renderFullDashboard(res.data);
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
   * Full Forensic Results Dashboard Renderer (Task 3)
   * ------------------------------------------------------------------------- */
  _renderFullDashboard(data) {
    if (!this.resultsContainer) return;
    this.resultsContainer.innerHTML = "";

    const risk = data.risk || {};
    const meta = data.email_metadata || {};
    const auth = data.authentication || {};
    const anomalies = data.header_anomalies?.anomalies || [];
    const origin = data.origin || {};
    const urls = data.url_analysis || {};
    const domain = data.domain_analysis || {};
    const content = data.content_analysis || {};
    const attachments = data.attachments || [];

    const root = createSafeElement("div", { className: "dashboard-root" });

    const riskLevelCfg = labels.getRiskLevel(risk.label);

    // -----------------------------------------------------------------------
    // Row 1: Executive Grid (Aperture Gauge + Executive Verdict)
    // -----------------------------------------------------------------------
    const heroRow = createSafeElement("div", { className: "dashboard-hero-row" });

    // 1. Aperture Gauge (Streamlined, clean)
    const gaugeEl = renderRiskGauge(risk, config.weights, { showBreakdown: false });
    heroRow.appendChild(gaugeEl);

    // 2. Executive Verdict Card
    const verdictCard = createSafeElement("div", {
      className: "card card-elevated verdict-card",
      children: [
        // Status Badge
        createSafeElement("div", {
          className: "verdict-status-badge",
          children: [
            createSafeElement("span", {
              className: `badge ${riskLevelCfg.badgeClass}`,
              style: "font-size: var(--text-sm); padding: var(--space-1) var(--space-4);",
              children: [
                createSafeElement("span", { className: "badge-dot" }),
                document.createTextNode(riskLevelCfg.name),
              ],
            }),
          ],
        }),

        // Primary Verdict Headline (focused on completion for accessibility)
        createSafeElement("h1", {
          id: "verdictHeadline",
          className: "verdict-headline",
          attributes: { tabindex: "-1" },
          text: riskLevelCfg.headline,
        }),

        // Plain-Language Verdict Sentence
        createSafeElement("p", {
          className: "verdict-sentence",
          text: riskLevelCfg.sentence,
        }),

        // Clean Email Metadata Summary
        createSafeElement("div", {
          className: "verdict-meta-grid",
          children: [
            createSafeElement("div", {
              className: "verdict-meta-item",
              children: [
                createSafeElement("strong", { text: "Subject" }),
                createSafeElement("span", {
                  className: "font-semibold",
                  text: meta.subject || "(No Subject Provided)",
                }),
              ],
            }),
            createSafeElement("div", {
              className: "verdict-meta-item",
              children: [
                createSafeElement("strong", { text: "From" }),
                createSafeElement("span", { text: meta.from ? defangEmail(meta.from) : "(Unknown)" }),
              ],
            }),
            createSafeElement("div", {
              className: "verdict-meta-item",
              children: [
                createSafeElement("strong", { text: "To" }),
                createSafeElement("span", { text: meta.to ? defangEmail(meta.to) : "(Unknown)" }),
              ],
            }),
            createSafeElement("div", {
              className: "verdict-meta-item",
              children: [
                createSafeElement("strong", { text: "Date" }),
                createSafeElement("span", { text: meta.date || "Not recorded" }),
              ],
            }),
          ],
        }),
      ],
    });

    heroRow.appendChild(verdictCard);
    root.appendChild(heroRow);

    // -----------------------------------------------------------------------
    // Row 2: "What you should do" Action Checklist Card
    // -----------------------------------------------------------------------
    const actionCard = createSafeElement("div", {
      className: "card card-elevated action-card",
      children: [
        createSafeElement("div", {
          className: "card-header",
          children: [
            createSafeElement("h2", {
              className: "card-title",
              text: labels.sections.actionsTitle,
            }),
          ],
        }),
        createSafeElement("ul", {
          className: "action-checklist",
          attributes: { "aria-label": "Recommended steps for this email" },
          children: riskLevelCfg.actions.map((act) =>
            createSafeElement("li", {
              className: "action-item",
              children: [
                createSafeElement("span", {
                  className: "action-bullet-icon",
                  attributes: { "aria-hidden": "true" },
                  text: "➜",
                }),
                createSafeElement("span", { text: act }),
              ],
            })
          ),
        }),
        // Action Toolbar (Responsive, thumb-friendly buttons)
        createSafeElement("div", {
          className: "action-toolbar",
          children: [
            createSafeElement("button", {
              className: "btn btn-primary btn-lg btn-reset-action",
              attributes: { type: "button", title: "Clear current results and analyze another email" },
              text: labels.actions.reset,
            }),
            createSafeElement("button", {
              className: "btn btn-secondary btn-print-action",
              attributes: { type: "button", title: "Print or Save as PDF" },
              text: labels.actions.printReport,
            }),
            data.report_url
              ? createSafeElement("button", {
                  className: "btn btn-secondary btn-report-action",
                  attributes: { type: "button", title: "Open Standalone HTML Report" },
                  text: labels.actions.viewReport,
                })
              : null,
            createSafeElement("button", {
              className: "btn btn-ghost btn-json-action",
              attributes: { type: "button", title: "Download Raw Analysis JSON" },
              text: labels.actions.downloadJson,
            }),
          ].filter(Boolean),
        }),
      ],
    });

    // Wire up Action Toolbar buttons on actionCard
    const printBtn = actionCard.querySelector(".btn-print-action");
    if (printBtn) {
      printBtn.addEventListener("click", () => window.print());
    }

    const reportBtn = actionCard.querySelector(".btn-report-action");
    if (reportBtn && data.report_url) {
      reportBtn.addEventListener("click", () => {
        const mask = Boolean(this.maskToggle && this.maskToggle.checked);
        const reportUrl = `${data.report_url}${mask ? "?mask=1" : ""}`;
        window.open(reportUrl, "_blank", "noopener,noreferrer");
      });
    }

    const jsonBtn = actionCard.querySelector(".btn-json-action");
    if (jsonBtn) {
      jsonBtn.addEventListener("click", () => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `phishlens_analysis_${data.id || "export"}.json`;
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    const resetBtn = actionCard.querySelector(".btn-reset-action");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        this._clearSelectedFile();
        if (this.rawTextarea) {
          this.rawTextarea.value = "";
          this.rawTextarea.dispatchEvent(new Event("input"));
        }
        if (this.resultsContainer) {
          this.resultsContainer.innerHTML = "";
        }
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    }

    root.appendChild(actionCard);

    // -----------------------------------------------------------------------
    // Row 3: "Why we think so" (Unified Plain-Language Evidence & Explanations)
    // -----------------------------------------------------------------------
    const reasonsEl = renderWhyWeThinkSo(risk);
    root.appendChild(reasonsEl);

    // -----------------------------------------------------------------------
    // Row 4: "Where did it come from?" (Plain Sentence + Map + Responsive Hop Cards)
    // -----------------------------------------------------------------------
    const originEl = renderOriginSection(origin);
    root.appendChild(originEl);

    // -----------------------------------------------------------------------
    // Row 5: "Links and attachments in this email" (Safe vs Suspicious Categorized)
    // -----------------------------------------------------------------------
    const linksEl = renderLinksAndAttachments(urls, attachments);
    root.appendChild(linksEl);


    // -----------------------------------------------------------------------
    // Row 6: Collapsible "Technical Details (for Analysts)" Drawer
    // -----------------------------------------------------------------------
    const analystEl = renderAnalystDrawer(data, config.weights);
    root.appendChild(analystEl);

    this.resultsContainer.appendChild(root);
    initCopyButtons(this.resultsContainer);

    this.resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });

    // Accessibility: shift focus to verdict headline and announce completion
    const verdictHeadline = document.getElementById("verdictHeadline");
    if (verdictHeadline) {
      verdictHeadline.focus();
    }
    announceScreenReader(`Email analysis complete. Verdict: ${riskLevelCfg.name}. ${riskLevelCfg.headline}`);
  }

}

export const app = new AppController();

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => app.init());
} else {
  app.init();
}
