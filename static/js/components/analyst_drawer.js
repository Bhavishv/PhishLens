/**
 * PhishLens Collapsible "Technical Details (for Analysts)" Drawer Component
 * Consolidates all deep forensic telemetry into a closed-by-default collapsible section:
 * - Category risk scoring breakdown
 * - Raw cryptographic authentication records (SPF, DKIM, DMARC)
 * - Header anomaly records & RFC compliance flags
 * - Sender domain WHOIS age, lookalike matching, and NLP model probabilities
 * - Full MTA relay hop timeline & 6-column structured routing telemetry table
 * - Raw SHA-256 hashes for message and MIME attachments
 * - Complete formatted raw JSON viewer with copy and download actions
 */

import { createSafeElement, defangDomain } from "../defang.js";
import { labels } from "../labels.js";
import { renderCategoryBreakdown } from "./gauge.js";
import { renderHopTimeline } from "./timeline.js";
import { renderHopTable } from "./map.js";

/**
 * Format bytes into readable format.
 */
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Render the complete Analyst Forensic Drawer.
 *
 * @param {Object} data - Full backend analysis JSON payload
 * @param {Object} weights - Category scoring maximum weights
 * @returns {HTMLElement}
 */
export function renderAnalystDrawer(data = {}, weights = {}) {
  const risk = data.risk || {};
  const meta = data.email_metadata || {};
  const auth = data.authentication || {};
  const anomalies = data.header_anomalies?.anomalies || [];
  const origin = data.origin || {};
  const domain = data.domain_analysis || {};
  const content = data.content_analysis || {};
  const attachments = data.attachments || [];

  const drawer = createSafeElement("details", {
    className: "collapsible card card-elevated analyst-drawer",
    attributes: { "aria-label": "Technical details for forensic analysts" },
  });

  // -------------------------------------------------------------------------
  // Summary Header (Closed by default)
  // -------------------------------------------------------------------------
  const summary = createSafeElement("summary", {
    className: "analyst-drawer-summary",
    children: [
      createSafeElement("div", {
        className: "analyst-summary-left",
        children: [
          createSafeElement("h2", {
            className: "analyst-drawer-title font-bold",
            text: labels.sections.analystTitle,
          }),
          createSafeElement("p", {
            className: "text-muted analyst-drawer-subtitle",
            text: labels.sections.analystSubtitle,
          }),
        ],
      }),
      createSafeElement("span", {
        className: "badge badge-neutral analyst-summary-badge",
        text: "Technical Forensics",
      }),
    ],
  });
  drawer.appendChild(summary);

  // -------------------------------------------------------------------------
  // Collapsible Body
  // -------------------------------------------------------------------------
  const body = createSafeElement("div", {
    className: "collapsible-body analyst-drawer-body",
  });

  // 1. Scoring Category Breakdown
  const scoringSection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("h3", {
        className: "analyst-subheading",
        text: "1. Threat Score Category Breakdown",
      }),
      createSafeElement("p", {
        className: "text-muted",
        style: "font-size: var(--text-xs); margin-bottom: var(--space-3);",
        text: `Weighted point distribution totaling ${risk.score || 0} / 100 points`,
      }),
      renderCategoryBreakdown(risk.breakdown, weights),
    ],
  });
  body.appendChild(scoringSection);

  // 2. Cryptographic Authentication (SPF, DKIM, DMARC)
  const authSection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("h3", {
        className: "analyst-subheading",
        text: "2. Cryptographic Authentication Records",
      }),
      createSafeElement("div", {
        className: "auth-grid",
        style: "margin-top: var(--space-3);",
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
    ],
  });
  body.appendChild(authSection);

  // 3. Header Anomalies
  const anomalySection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("h3", {
        className: "analyst-subheading",
        text: `3. Header Inconsistencies & RFC Anomalies (${anomalies.length})`,
      }),
      anomalies.length > 0
        ? createSafeElement("ul", {
            className: "analyst-anomalies-list",
            children: anomalies.map((a) =>
              createSafeElement("li", {
                className: "analyst-anomaly-item",
                children: [
                  createSafeElement("span", {
                    className: `badge badge-${a.severity === "high" ? "critical" : "suspicious"} font-mono`,
                    style: "font-size: 0.65rem;",
                    text: (a.severity || "info").toUpperCase(),
                  }),
                  createSafeElement("code", {
                    className: "font-mono font-bold",
                    style: "font-size: var(--text-xs);",
                    text: a.id || "ANOMALY",
                  }),
                  createSafeElement("span", {
                    style: "font-size: var(--text-xs); color: var(--text-muted);",
                    text: `— ${a.message || "Unspecified anomaly"}`,
                  }),
                ],
              })
            ),
          })
        : createSafeElement("p", {
            className: "text-muted",
            style: "font-size: var(--text-xs); padding: var(--space-2) 0;",
            text: "No header inconsistencies or RFC anomalies were detected in this message.",
          }),
    ],
  });
  body.appendChild(anomalySection);

  // 4. Domain Reputation & Content NLP Forensics
  const domainAndNlpSection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("h3", {
        className: "analyst-subheading",
        text: "4. Domain Reputation & NLP Heuristic Forensics",
      }),
      createSafeElement("div", {
        className: "analyst-two-col-grid",
        children: [
          // Left: Domain Intelligence
          createSafeElement("div", {
            className: "auth-badge-card",
            children: [
              createSafeElement("div", { className: "font-semibold", text: "Sender Domain WHOIS Telemetry" }),
              createSafeElement("div", {
                className: "flex justify-between items-center text-xs",
                style: "margin-top: 4px;",
                children: [
                  createSafeElement("span", { className: "text-muted", text: "Sender Domain:" }),
                  createSafeElement("code", { text: defangDomain(meta.from_domain || domain.domain || "Unknown") }),
                ],
              }),
              createSafeElement("div", {
                className: "flex justify-between items-center text-xs",
                children: [
                  createSafeElement("span", { className: "text-muted", text: "Domain Age:" }),
                  createSafeElement("span", {
                    className: domain.is_newly_registered ? "text-critical font-bold" : "",
                    text: domain.age_days !== null && domain.age_days !== undefined
                      ? `${domain.age_days} days (${domain.is_newly_registered ? "Newly Registered" : "Established"})`
                      : "Unknown / Unresolved",
                  }),
                ],
              }),
              createSafeElement("div", {
                className: "flex justify-between items-center text-xs",
                children: [
                  createSafeElement("span", { className: "text-muted", text: "Lookalike / Typosquatting:" }),
                  createSafeElement("span", {
                    className: domain.lookalike?.is_lookalike ? "text-critical font-bold" : "",
                    text: domain.lookalike?.is_lookalike
                      ? `Resembles ${domain.lookalike.matched_brand} (dist: ${domain.lookalike.edit_distance})`
                      : "None detected",
                  }),
                ],
              }),
              createSafeElement("div", {
                className: "flex justify-between items-center text-xs",
                children: [
                  createSafeElement("span", { className: "text-muted", text: "IDN / Punycode:" }),
                  createSafeElement("span", {
                    text: domain.has_punycode ? "Punycode (xn--) Active" : "Standard ASCII",
                  }),
                ],
              }),
            ],
          }),

          // Right: Content NLP Assessment
          createSafeElement("div", {
            className: "auth-badge-card",
            children: [
              createSafeElement("div", {
                className: "flex justify-between items-center",
                children: [
                  createSafeElement("span", { className: "font-semibold", text: "Content NLP Classifier" }),
                  createSafeElement("span", {
                    className: `badge badge-${content.label === "phishing" ? "critical" : "low"}`,
                    text: `${(content.label || "UNKNOWN").toUpperCase()} (${Math.round((content.probability || 0) * 100)}%)`,
                  }),
                ],
              }),
              createSafeElement("div", {
                className: "text-muted",
                style: "font-size: var(--text-xs); margin-top: 4px;",
                text: content.fallback
                  ? "Keyword heuristic fallback active (model offline)"
                  : `TF-IDF Logistic Regression (${content.model_version || "v1"})`,
              }),
              content.top_indicative_terms && content.top_indicative_terms.length > 0
                ? createSafeElement("div", {
                    style: "margin-top: var(--space-2);",
                    children: [
                      createSafeElement("span", {
                        className: "text-muted",
                        style: "font-size: var(--text-xs); display: block; margin-bottom: 2px;",
                        text: "Key Indicative Tokens:",
                      }),
                      createSafeElement("div", {
                        style: "display: flex; gap: 4px; flex-wrap: wrap;",
                        children: content.top_indicative_terms.map((term) =>
                          createSafeElement("span", { className: "badge badge-neutral font-mono", text: term })
                        ),
                      }),
                    ],
                  })
                : null,
            ].filter(Boolean),
          }),
        ],
      }),
    ],
  });
  body.appendChild(domainAndNlpSection);

  // 5. Full MTA Relay Hop Timeline & 6-Column Structured Table
  const mtaSection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("h3", {
        className: "analyst-subheading",
        text: "5. MTA Relay Hop Chain & Tabular Routing Telemetry",
      }),
      renderHopTimeline(origin),
      createSafeElement("div", {
        className: "table-responsive",
        style: "margin-top: var(--space-4);",
        children: [
          renderHopTable(origin.relay_chain, origin.geolocation?.all_hops, origin.geolocation?.probable_origin),
        ],
      }),
    ],
  });
  body.appendChild(mtaSection);

  // 6. SHA-256 Hashes
  const messageHash = meta.sha256 || data.id || "";
  const hashSection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("h3", {
        className: "analyst-subheading",
        text: "6. Cryptographic SHA-256 Hashes",
      }),
      createSafeElement("div", {
        className: "analyst-hash-box",
        children: [
          createSafeElement("div", {
            className: "analyst-hash-item",
            children: [
              createSafeElement("strong", { text: "Message Source SHA-256:" }),
              createSafeElement("div", {
                className: "flex items-center gap-2",
                style: "margin-top: 4px;",
                children: [
                  createSafeElement("code", {
                    className: "font-mono font-bold analyst-hash-code",
                    text: messageHash || "None recorded",
                  }),
                  messageHash
                    ? createSafeElement("button", {
                        className: "btn-copy",
                        attributes: {
                          "data-copy-btn": "",
                          "data-copy-text": messageHash,
                          "aria-label": "Copy Message Hash",
                          title: "Copy SHA-256 Hash",
                        },
                        children: [document.createTextNode("📋")],
                      })
                    : null,
                ].filter(Boolean),
              }),
            ],
          }),
          attachments.length > 0
            ? createSafeElement("div", {
                style: "margin-top: var(--space-3);",
                children: [
                  createSafeElement("strong", { text: `Attachment Hashes (${attachments.length}):` }),
                  createSafeElement("div", {
                    style: "display: flex; flex-direction: column; gap: var(--space-2); margin-top: 4px;",
                    children: attachments.map((att) =>
                      createSafeElement("div", {
                        className: "flex items-center justify-between gap-2 text-xs",
                        children: [
                          createSafeElement("span", {
                            className: "font-semibold",
                            text: defangDomain(att.filename || "file"),
                          }),
                          createSafeElement("div", {
                            className: "flex items-center gap-2",
                            children: [
                              createSafeElement("code", {
                                className: "font-mono analyst-hash-code",
                                text: att.sha256 || "None",
                              }),
                              att.sha256
                                ? createSafeElement("button", {
                                    className: "btn-copy",
                                    attributes: {
                                      "data-copy-btn": "",
                                      "data-copy-text": att.sha256,
                                      "aria-label": `Copy Hash for ${att.filename}`,
                                      title: "Copy SHA-256 Hash",
                                    },
                                    children: [document.createTextNode("📋")],
                                  })
                                : null,
                            ].filter(Boolean),
                          }),
                        ],
                      })
                    ),
                  }),
                ],
              })
            : null,
        ].filter(Boolean),
      }),
    ],
  });
  body.appendChild(hashSection);

  // 7. Complete Raw JSON Viewer
  const jsonString = JSON.stringify(data, null, 2);
  const jsonSection = createSafeElement("div", {
    className: "analyst-subsection",
    children: [
      createSafeElement("div", {
        className: "flex justify-between items-center flex-wrap gap-2",
        children: [
          createSafeElement("h3", {
            className: "analyst-subheading",
            text: "7. Complete Raw Forensic JSON Payload",
          }),
          createSafeElement("div", {
            className: "flex items-center gap-2",
            children: [
              createSafeElement("button", {
                className: "btn btn-secondary btn-sm",
                attributes: {
                  type: "button",
                  "data-copy-btn": "",
                  "data-copy-text": jsonString,
                  "aria-label": "Copy complete JSON payload",
                },
                text: "📋 Copy Raw JSON",
              }),
              createSafeElement("button", {
                className: "btn btn-ghost btn-sm btn-download-json-analyst",
                attributes: { type: "button", title: "Download Raw JSON" },
                text: "💾 Download .json",
              }),
            ],
          }),
        ],
      }),
      createSafeElement("pre", {
        className: "json font-mono analyst-raw-json",
        style: "margin-top: var(--space-3);",
        text: jsonString,
      }),
    ],
  });

  // Wire up the JSON download button
  const downloadBtn = jsonSection.querySelector(".btn-download-json-analyst");
  if (downloadBtn) {
    downloadBtn.addEventListener("click", () => {
      const blob = new Blob([jsonString], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishlens_forensics_${data.id || "export"}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  body.appendChild(jsonSection);

  drawer.appendChild(body);
  return drawer;
}
