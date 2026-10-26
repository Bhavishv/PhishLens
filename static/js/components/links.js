/**
 * PhishLens "Links and Attachments" Component
 * Categorizes extracted URLs into Suspicious vs Standard, provides copy tools,
 * displays deceptive anchor alerts, defangs all entities, and inventories file attachments.
 */

import { createSafeElement, defangUrl, defangDomain } from "../defang.js";
import { labels } from "../labels.js";

const RISKY_EXTENSIONS = /\.(exe|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|zip|rar|7z|tar|gz|iso|img|hta|docm|xlsm|pptm)$/i;

/**
 * Format bytes into human-readable string.
 */
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

/**
 * Render the complete Links and Attachments card.
 *
 * @param {Object} urlsData - API url_analysis data
 * @param {Array} attachments - API attachments array
 * @returns {HTMLElement}
 */
export function renderLinksAndAttachments(urlsData = {}, attachments = []) {
  const urlFindings = urlsData.url_findings || [];
  const totalUrls = urlsData.total_urls || urlFindings.length;
  const totalAtts = (attachments && attachments.length) || 0;

  // Empty State: Neither links nor attachments
  if (urlFindings.length === 0 && totalAtts === 0) {
    return createSafeElement("div", {
      className: "card card-elevated links-card",
      children: [
        createSafeElement("div", {
          className: "card-header",
          children: [
            createSafeElement("h2", {
              className: "card-title",
              text: labels.links.title,
            }),
          ],
        }),
        createSafeElement("p", {
          className: "text-muted",
          style: "padding: var(--space-4) 0; font-size: var(--text-sm);",
          text: labels.links.noLinksOrAttachments,
        }),
      ],
    });
  }

  // Split into Suspicious vs Standard
  const suspiciousUrls = [];
  const standardUrls = [];

  urlFindings.forEach((uf) => {
    const hasFlags = Array.isArray(uf.flags) && uf.flags.length > 0;
    const isSuspicious = hasFlags || (uf.risk_score && uf.risk_score > 0) || uf.is_suspicious;
    if (isSuspicious) {
      suspiciousUrls.push(uf);
    } else {
      standardUrls.push(uf);
    }
  });

  const container = createSafeElement("div", {
    className: "card card-elevated links-card",
  });

  // Header
  const header = createSafeElement("div", {
    className: "card-header",
    children: [
      createSafeElement("div", {
        children: [
          createSafeElement("h2", {
            className: "card-title",
            text: labels.links.title,
          }),
          createSafeElement("p", {
            className: "text-muted",
            style: "font-size: var(--text-xs); margin-top: 2px;",
            text: labels.links.subtitle,
          }),
        ],
      }),
      createSafeElement("span", {
        className: `badge ${suspiciousUrls.length > 0 ? "badge-critical" : "badge-neutral"}`,
        text: `${totalUrls} link${totalUrls === 1 ? "" : "s"} · ${totalAtts} file${totalAtts === 1 ? "" : "s"}`,
      }),
    ],
  });
  container.appendChild(header);

  // Safety Notice Banner
  const notice = createSafeElement("div", {
    className: "alert alert-info links-safety-notice",
    style: "margin: var(--space-4) 0; font-size: var(--text-xs);",
    children: [
      createSafeElement("span", {
        style: "font-weight: var(--weight-bold); margin-right: 4px;",
        text: "🛡️ Safety Notice:",
      }),
      document.createTextNode(labels.links.safetyNotice),
    ],
  });
  container.appendChild(notice);

  // 1. Suspicious Links Section
  if (suspiciousUrls.length > 0) {
    const suspGroup = createSafeElement("div", {
      className: "links-subgroup links-subgroup-suspicious",
      children: [
        createSafeElement("div", {
          className: "links-subgroup-title",
          children: [
            createSafeElement("span", { text: "⚠️ " }),
            createSafeElement("span", { text: `${labels.links.suspiciousTitle} (${suspiciousUrls.length})` }),
          ],
        }),
        createSafeElement("div", {
          className: "links-list",
          children: suspiciousUrls.map((uf) => _renderSuspiciousLinkItem(uf)),
        }),
      ],
    });
    container.appendChild(suspGroup);
  }

  // 2. Standard / Clean Links Section
  if (standardUrls.length > 0) {
    const cleanGroup = createSafeElement("div", {
      className: "links-subgroup links-subgroup-clean",
      style: "margin-top: var(--space-5);",
      children: [
        createSafeElement("div", {
          className: "links-subgroup-title",
          children: [
            createSafeElement("span", { text: "✓ " }),
            createSafeElement("span", { text: `${labels.links.cleanTitle} (${standardUrls.length})` }),
          ],
        }),
        createSafeElement("div", {
          className: "links-list",
          children: standardUrls.map((uf) => _renderStandardLinkItem(uf)),
        }),
      ],
    });
    container.appendChild(cleanGroup);
  }

  // 3. Attachments Section
  if (totalAtts > 0) {
    const hasRiskyFile = attachments.some((att) => RISKY_EXTENSIONS.test(att.filename || ""));

    const attachGroup = createSafeElement("div", {
      className: "links-subgroup links-subgroup-attachments",
      style: "margin-top: var(--space-5);",
      children: [
        createSafeElement("div", {
          className: "links-subgroup-title",
          children: [
            createSafeElement("span", { text: "📎 " }),
            createSafeElement("span", { text: `${labels.links.attachmentsTitle} (${totalAtts})` }),
          ],
        }),
        hasRiskyFile
          ? createSafeElement("div", {
              className: "alert alert-warning",
              style: "font-size: var(--text-xs); margin-bottom: var(--space-3);",
              text: labels.links.riskyAttachmentWarning,
            })
          : null,
        createSafeElement("div", {
          className: "attachments-grid",
          children: attachments.map((att) => _renderAttachmentItem(att)),
        }),
      ].filter(Boolean),
    });
    container.appendChild(attachGroup);
  }

  return container;
}

/**
 * Render a suspicious link card with deceptive anchor warning and risk flags.
 */
function _renderSuspiciousLinkItem(uf) {
  const defanged = defangUrl(uf.url);
  const flags = uf.flags || [];
  const anchor = (uf.anchor_text || "").trim();
  const hasMismatch = anchor && anchor !== uf.url && !uf.url.includes(anchor);

  return createSafeElement("div", {
    className: "link-item link-item-suspicious",
    children: [
      createSafeElement("div", {
        className: "link-item-main",
        children: [
          createSafeElement("div", {
            className: "link-destination-row",
            children: [
              createSafeElement("span", {
                className: "link-dest-label",
                text: "Destination:",
              }),
              createSafeElement("code", {
                className: "link-dest-code font-mono",
                text: defanged,
              }),
              createSafeElement("button", {
                className: "btn-copy",
                attributes: {
                  "data-copy-btn": "",
                  "data-copy-text": uf.url,
                  "aria-label": "Copy neutralized link",
                  title: labels.links.copyUrl,
                },
                children: [document.createTextNode("📋")],
              }),
            ],
          }),
          hasMismatch
            ? createSafeElement("div", {
                className: "link-mismatch-alert",
                children: [
                  createSafeElement("span", {
                    className: "font-semibold",
                    text: `Text shown in email: "${defangUrl(anchor)}" (does not match actual destination!)`,
                  }),
                ],
              })
            : null,
          flags.length > 0
            ? createSafeElement("div", {
                className: "link-flags-row",
                children: flags.map((fl) =>
                  createSafeElement("span", {
                    className: `badge badge-${fl.severity === "high" ? "critical" : "suspicious"}`,
                    text: fl.message || fl.id,
                  })
                ),
              })
            : null,
        ].filter(Boolean),
      }),
    ],
  });
}

/**
 * Render a standard/clean link card.
 */
function _renderStandardLinkItem(uf) {
  const defanged = defangUrl(uf.url);

  return createSafeElement("div", {
    className: "link-item link-item-clean",
    children: [
      createSafeElement("div", {
        className: "link-destination-row",
        children: [
          createSafeElement("code", {
            className: "link-dest-code font-mono",
            text: defanged,
          }),
          createSafeElement("button", {
            className: "btn-copy",
            attributes: {
              "data-copy-btn": "",
              "data-copy-text": uf.url,
              "aria-label": "Copy neutralized link",
              title: labels.links.copyUrl,
            },
            children: [document.createTextNode("📋")],
          }),
        ],
      }),
    ],
  });
}

/**
 * Render an individual attachment card.
 */
function _renderAttachmentItem(att) {
  const isRisky = RISKY_EXTENSIONS.test(att.filename || "");
  const sha = att.sha256 || "";
  const shaShort = sha ? `${sha.slice(0, 12)}...` : "None";

  return createSafeElement("div", {
    className: `attachment-card ${isRisky ? "attachment-card-risky" : ""}`,
    children: [
      createSafeElement("div", {
        className: "attachment-header",
        children: [
          createSafeElement("span", {
            className: "attachment-filename font-semibold",
            text: defangDomain(att.filename || "unnamed_attachment"),
          }),
          isRisky
            ? createSafeElement("span", {
                className: "badge badge-critical",
                text: "Executable / Script",
              })
            : null,
        ].filter(Boolean),
      }),
      createSafeElement("div", {
        className: "attachment-meta text-muted",
        children: [
          createSafeElement("span", { text: formatBytes(att.size || 0) }),
          createSafeElement("span", { text: " · " }),
          createSafeElement("span", { text: att.content_type || "application/octet-stream" }),
        ],
      }),
      sha
        ? createSafeElement("div", {
            className: "attachment-hash-row",
            children: [
              createSafeElement("span", { className: "text-muted font-mono", text: "SHA-256: " }),
              createSafeElement("code", { className: "font-mono", text: shaShort }),
              createSafeElement("button", {
                className: "btn-copy",
                attributes: {
                  "data-copy-btn": "",
                  "data-copy-text": sha,
                  "aria-label": "Copy SHA-256 hash",
                  title: labels.links.copyHash,
                },
                children: [document.createTextNode("📋")],
              }),
            ],
          })
        : null,
    ].filter(Boolean),
  });
}
