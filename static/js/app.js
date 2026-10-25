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
import { renderHopTimeline } from "./components/timeline.js";
import { renderOriginMapAndTable } from "./components/map.js";
import { initCopyButtons } from "./components/copy_button.js";

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

    // -----------------------------------------------------------------------
    // Row 1: Executive Grid (Aperture Gauge + Executive Verdict)
    // -----------------------------------------------------------------------
    const heroRow = createSafeElement("div", { className: "dashboard-hero-row" });

    // 1. Aperture Gauge
    const gaugeEl = renderRiskGauge(risk, config.weights);
    heroRow.appendChild(gaugeEl);

    // 2. Executive Verdict Card
    const badgeClass = `badge-${(risk.label || "low").toLowerCase().replace(" risk", "").replace(" ", "-")}`;
    const verdictCard = createSafeElement("div", {
      className: "card card-elevated verdict-card",
      children: [
        // Header
        createSafeElement("div", {
          className: "verdict-header-row",
          children: [
            createSafeElement("span", {
              className: `badge ${badgeClass}`,
              style: "font-size: var(--text-sm); padding: var(--space-1) var(--space-4);",
              children: [
                createSafeElement("span", { className: "badge-dot" }),
                document.createTextNode(`${risk.label || "Low Risk"} Verdict`),
              ],
            }),
            createSafeElement("div", {
              className: "flex items-center gap-2 flex-wrap",
              children: [
                createSafeElement("button", {
                  className: "btn btn-secondary btn-sm btn-print-action",
                  text: labels.actions.printReport,
                  attributes: { type: "button", title: "Print or Save as PDF" },
                }),
                data.report_url
                  ? createSafeElement("button", {
                      className: "btn btn-secondary btn-sm btn-report-action",
                      text: labels.actions.viewReport,
                      attributes: { type: "button", title: "Open Standalone Forensic HTML Report" },
                    })
                  : null,
                createSafeElement("button", {
                  className: "btn btn-ghost btn-sm btn-json-action",
                  text: labels.actions.downloadJson,
                  attributes: { type: "button", title: "Download Raw Analysis JSON" },
                }),
                createSafeElement("button", {
                  className: "btn btn-ghost btn-sm btn-reset-action",
                  text: labels.actions.reset,
                  attributes: { type: "button", title: "Clear and Analyze Another Email" },
                }),
              ].filter(Boolean),
            }),
          ],
        }),

        // Subject & Email Metadata
        createSafeElement("h2", {
          className: "verdict-subject",
          text: meta.subject || "(No Subject Provided)",
        }),

        createSafeElement("div", {
          className: "verdict-meta-grid",
          children: [
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
            createSafeElement("div", {
              className: "verdict-meta-item",
              children: [
                createSafeElement("strong", { text: "File SHA-256" }),
                createSafeElement("div", {
                  className: "flex items-center gap-2",
                  children: [
                    createSafeElement("code", {
                      className: "font-mono",
                      text: (data.file_sha256 || "").slice(0, 18) + "...",
                    }),
                    createSafeElement("button", {
                      className: "btn-copy",
                      attributes: {
                        "data-copy-btn": "",
                        "data-copy-text": data.file_sha256 || "",
                        "aria-label": "Copy SHA-256",
                        title: "Copy Hash",
                      },
                      children: [document.createTextNode("📋")],
                    }),
                  ],
                }),
              ],
            }),
          ],
        }),

        // Key Contributing Factors List
        createSafeElement("div", {
          className: "reasons-section",
          children: [
            createSafeElement("div", {
              className: "card-title",
              style: "font-size: var(--text-sm); margin-bottom: var(--space-2);",
              text: "Key Forensic Risk Indicators",
            }),
            createSafeElement("div", {
              className: "reasons-list",
              children: (risk.reasons && risk.reasons.length > 0)
                ? risk.reasons.map((r) => {
                    const parts = r.split(":");
                    const pts = parts[0] || "+0";
                    const desc = parts.slice(1).join(":").trim();
                    return createSafeElement("div", {
                      className: "reason-item",
                      children: [
                        createSafeElement("span", { className: "reason-pill", text: pts }),
                        createSafeElement("span", { text: desc }),
                      ],
                    });
                  })
                : [
                    createSafeElement("div", {
                      className: "text-muted",
                      style: "font-size: var(--text-sm);",
                      text: "No significant malicious indicators detected in this email.",
                    }),
                  ],
            }),
          ],
        }),
      ],
    });

    // Wire up Action Toolbar buttons
    const printBtn = verdictCard.querySelector(".btn-print-action");
    if (printBtn) {
      printBtn.addEventListener("click", () => window.print());
    }

    const reportBtn = verdictCard.querySelector(".btn-report-action");
    if (reportBtn && data.report_url) {
      reportBtn.addEventListener("click", () => {
        const mask = Boolean(this.maskToggle && this.maskToggle.checked);
        const reportUrl = `${data.report_url}${mask ? "?mask=1" : ""}`;
        window.open(reportUrl, "_blank", "noopener,noreferrer");
      });
    }

    const jsonBtn = verdictCard.querySelector(".btn-json-action");
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

    const resetBtn = verdictCard.querySelector(".btn-reset-action");
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

    heroRow.appendChild(verdictCard);
    root.appendChild(heroRow);

    // -----------------------------------------------------------------------
    // Row 2: Two-column Security Checks (Authentication & Domain Intelligence)
    // -----------------------------------------------------------------------
    const checkRow = createSafeElement("div", {
      style: "display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: var(--space-6);",
    });

    // Col A: Cryptographic Authentication
    const authCard = createSafeElement("div", {
      className: "card card-elevated",
      children: [
        createSafeElement("div", {
          className: "card-header",
          children: [
            createSafeElement("span", { className: "card-title", text: "Cryptographic Authentication" }),
            createSafeElement("span", { className: "text-muted", style: "font-size: var(--text-xs);", text: "SPF · DKIM · DMARC" }),
          ],
        }),
        createSafeElement("div", {
          className: "auth-grid",
          children: ["spf", "dkim", "dmarc"].map((mech) => {
            const entry = auth[mech] || {};
            const status = (entry.status || "none").toLowerCase();
            const isPass = status === "pass";
            const isFail = ["fail", "softfail", "permerror"].includes(status);
            const badgeCls = isPass ? "badge-low" : isFail ? "badge-critical" : "badge-neutral";

            return createSafeElement("div", {
              className: "auth-badge-card",
              children: [
                createSafeElement("div", {
                  className: "auth-badge-header",
                  children: [
                    createSafeElement("span", { className: "auth-badge-title", text: mech.toUpperCase() }),
                    createSafeElement("span", { className: `badge ${badgeCls}`, text: status.toUpperCase() }),
                  ],
                }),
                createSafeElement("div", {
                  className: "auth-badge-desc",
                  text: entry.details || "No verification record found.",
                }),
              ],
            });
          }),
        }),
        // Header Anomalies sub-list
        anomalies.length > 0
          ? createSafeElement("div", {
              style: "margin-top: var(--space-4); padding-top: var(--space-3); border-top: 1px solid var(--border-subtle);",
              children: [
                createSafeElement("div", {
                  className: "font-semibold",
                  style: "font-size: var(--text-sm); margin-bottom: var(--space-2);",
                  text: `Header Inconsistencies (${anomalies.length})`,
                }),
                createSafeElement("ul", {
                  style: "padding-left: var(--space-4); font-size: var(--text-xs); color: var(--text-muted);",
                  children: anomalies.map((a) =>
                    createSafeElement("li", {
                      style: "margin-bottom: 4px;",
                      children: [
                        createSafeElement("span", {
                          className: `badge badge-${a.severity === "high" ? "critical" : "suspicious"}`,
                          style: "font-size: 0.65rem; margin-right: 6px; padding: 0 4px;",
                          text: a.severity.toUpperCase(),
                        }),
                        document.createTextNode(a.message || a.id),
                      ],
                    })
                  ),
                }),
              ],
            })
          : null,
      ].filter(Boolean),
    });
    checkRow.appendChild(authCard);

    // Col B: Domain Intelligence & Content ML
    const domainCard = createSafeElement("div", {
      className: "card card-elevated",
      children: [
        createSafeElement("div", {
          className: "card-header",
          children: [
            createSafeElement("span", { className: "card-title", text: "Domain Reputation & Content ML" }),
            createSafeElement("span", { className: "text-muted", style: "font-size: var(--text-xs);", text: "WHOIS & NLP" }),
          ],
        }),
        createSafeElement("div", {
          style: "display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3); margin-bottom: var(--space-4); font-size: var(--text-xs);",
          children: [
            createSafeElement("div", {
              className: "auth-badge-card",
              children: [
                createSafeElement("strong", { text: "Sender Domain Age" }),
                createSafeElement("span", {
                  className: domain.is_newly_registered ? "text-critical font-bold" : "text-main",
                  text: domain.age_days !== null && domain.age_days !== undefined
                    ? `${domain.age_days} days old ${domain.is_newly_registered ? "(Newly Registered)" : ""}`
                    : "Age Unknown",
                }),
              ],
            }),
            createSafeElement("div", {
              className: "auth-badge-card",
              children: [
                createSafeElement("strong", { text: "Typosquatting Check" }),
                createSafeElement("span", {
                  className: domain.lookalike?.is_lookalike ? "text-critical font-bold" : "text-main",
                  text: domain.lookalike?.is_lookalike
                    ? `Resembles ${domain.lookalike.matched_brand}`
                    : "No Brand Match",
                }),
              ],
            }),
          ],
        }),
        // Content ML summary
        createSafeElement("div", {
          className: "auth-badge-card",
          children: [
            createSafeElement("div", {
              className: "flex justify-between items-center",
              children: [
                createSafeElement("strong", { text: "NLP Classifier Assessment" }),
                createSafeElement("span", {
                  className: `badge badge-${content.label === "phishing" ? "critical" : "low"}`,
                  text: `${content.label ? content.label.toUpperCase() : "UNKNOWN"} (${Math.round((content.probability || 0) * 100)}%)`,
                }),
              ],
            }),
            createSafeElement("div", {
              className: "text-muted",
              style: "font-size: var(--text-xs); margin-top: 4px;",
              text: content.fallback
                ? "Keyword heuristic fallback active (trained model unavailable)"
                : `TF-IDF Logistic Regression (${content.model_version || "v1"})`,
            }),
            (content.top_indicative_terms && content.top_indicative_terms.length > 0)
              ? createSafeElement("div", {
                  style: "display: flex; gap: 4px; flex-wrap: wrap; margin-top: var(--space-2);",
                  children: content.top_indicative_terms.map((term) =>
                    createSafeElement("span", { className: "badge badge-neutral", text: term })
                  ),
                })
              : null,
          ].filter(Boolean),
        }),
      ],
    });
    checkRow.appendChild(domainCard);
    root.appendChild(checkRow);

    // -----------------------------------------------------------------------
    // Row 3: Deceptive URL Findings Table
    // -----------------------------------------------------------------------
    const urlFindings = urls.url_findings || [];
    const urlCard = createSafeElement("div", {
      className: "card card-elevated",
      children: [
        createSafeElement("div", {
          className: "card-header",
          children: [
            createSafeElement("span", {
              className: "card-title",
              text: `Extracted URLs & Deceptive Links (${urls.total_urls || 0} found, ${urls.suspicious_url_count || 0} suspicious)`,
            }),
            createSafeElement("span", {
              className: `badge badge-${urls.risk_indicator === "high" ? "critical" : "neutral"}`,
              text: `URL Threat: ${(urls.risk_indicator || "low").toUpperCase()}`,
            }),
          ],
        }),
        createSafeElement("div", {
          className: "table-responsive",
          children: [
            createSafeElement("table", {
              className: "telemetry-table",
              attributes: { "aria-label": "Extracted email URLs table" },
              children: [
                createSafeElement("thead", {
                  children: [
                    createSafeElement("tr", {
                      children: [
                        createSafeElement("th", { text: "Defanged Destination URL" }),
                        createSafeElement("th", { text: "Anchor / Visible Text" }),
                        createSafeElement("th", { text: "Risk Flags" }),
                        createSafeElement("th", { text: "Actions" }),
                      ],
                    }),
                  ],
                }),
                createSafeElement("tbody", {
                  children: urlFindings.length > 0
                    ? urlFindings.map((uf) => {
                        const defanged = defangUrl(uf.url);
                        const flags = uf.flags || [];
                        return createSafeElement("tr", {
                          children: [
                            createSafeElement("td", {
                              children: [createSafeElement("code", { text: defanged })],
                            }),
                            createSafeElement("td", {
                              className: "text-muted",
                              text: uf.anchor_text ? defangUrl(uf.anchor_text) : "—",
                            }),
                            createSafeElement("td", {
                              children: flags.map((fl) =>
                                createSafeElement("span", {
                                  className: `badge badge-${fl.severity === "high" ? "critical" : "suspicious"}`,
                                  style: "font-size: 0.65rem; margin-right: 4px;",
                                  text: fl.message || fl.id,
                                })
                              ),
                            }),
                            createSafeElement("td", {
                              children: [
                                createSafeElement("button", {
                                  className: "btn-copy",
                                  attributes: {
                                    "data-copy-btn": "",
                                    "data-copy-text": uf.url,
                                    "aria-label": "Copy URL",
                                    title: "Copy URL",
                                  },
                                  children: [document.createTextNode("📋")],
                                }),
                              ],
                            }),
                          ],
                        });
                      })
                    : [
                        createSafeElement("tr", {
                          children: [
                            createSafeElement("td", {
                              attributes: { colspan: "4" },
                              className: "text-center text-muted",
                              text: "No URLs found in email body.",
                            }),
                          ],
                        }),
                      ],
                }),
              ],
            }),
          ],
        }),
      ],
    });
    root.appendChild(urlCard);

    // -----------------------------------------------------------------------
    // Row 4: MTA Relay Timeline & Geographic Origin (Interactive Map + Table)
    // -----------------------------------------------------------------------
    const timelineEl = renderHopTimeline(origin);
    root.appendChild(timelineEl);

    const mapAndTableEl = renderOriginMapAndTable(origin);
    root.appendChild(mapAndTableEl);

    // -----------------------------------------------------------------------
    // Row 5: Attachments (if any)
    // -----------------------------------------------------------------------
    if (attachments && attachments.length > 0) {
      const attachCard = createSafeElement("div", {
        className: "card card-elevated",
        children: [
          createSafeElement("div", {
            className: "card-header",
            children: [
              createSafeElement("span", {
                className: "card-title",
                text: `MIME Attachments (${attachments.length})`,
              }),
            ],
          }),
          createSafeElement("div", {
            className: "table-responsive",
            children: [
              createSafeElement("table", {
                className: "telemetry-table",
                children: [
                  createSafeElement("thead", {
                    children: [
                      createSafeElement("tr", {
                        children: [
                          createSafeElement("th", { text: "Filename" }),
                          createSafeElement("th", { text: "Type" }),
                          createSafeElement("th", { text: "Size" }),
                          createSafeElement("th", { text: "SHA-256 Hash" }),
                        ],
                      }),
                    ],
                  }),
                  createSafeElement("tbody", {
                    children: attachments.map((att) =>
                      createSafeElement("tr", {
                        children: [
                          createSafeElement("td", { text: defangDomain(att.filename || "unknown") }),
                          createSafeElement("td", { className: "text-muted", text: att.content_type || "application/octet-stream" }),
                          createSafeElement("td", { text: this._formatBytes(att.size || 0) }),
                          createSafeElement("td", {
                            children: [
                              createSafeElement("code", { text: (att.sha256 || "").slice(0, 16) + "..." }),
                              createSafeElement("button", {
                                className: "btn-copy",
                                style: "margin-left: 6px;",
                                attributes: {
                                  "data-copy-btn": "",
                                  "data-copy-text": att.sha256 || "",
                                  "aria-label": "Copy Attachment Hash",
                                  title: "Copy Hash",
                                },
                                children: [document.createTextNode("📋")],
                              }),
                            ],
                          }),
                        ],
                      })
                    ),
                  }),
                ],
              }),
            ],
          }),
        ],
      });
      root.appendChild(attachCard);
    }

    // -----------------------------------------------------------------------
    // Row 6: Collapsible Raw Forensic Telemetry
    // -----------------------------------------------------------------------
    const rawDetails = createSafeElement("details", {
      className: "collapsible",
      style: "margin-top: var(--space-4);",
      children: [
        createSafeElement("summary", {
          children: [
            createSafeElement("span", { text: "Inspect Complete Raw Forensic JSON Telemetry" }),
            createSafeElement("span", { className: "text-muted", style: "font-size: var(--text-xs);", text: "Developers & Auditors" }),
          ],
        }),
        createSafeElement("div", {
          className: "collapsible-body",
          children: [
            createSafeElement("pre", {
              className: "json font-mono",
              text: JSON.stringify(data, null, 2),
            }),
          ],
        }),
      ],
    });
    root.appendChild(rawDetails);

    this.resultsContainer.appendChild(root);
    initCopyButtons(this.resultsContainer);

    this.resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

export const app = new AppController();

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => app.init());
} else {
  app.init();
}
