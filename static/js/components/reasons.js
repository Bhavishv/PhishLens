/**
 * PhishLens "Why we think so" Component
 * Unified plain-language forensic evidence card. Replaces dense technical tables
 * with Grade-8 explanations, severity icons, and expandable "What does this mean?" guides.
 */

import { createSafeElement } from "../defang.js";
import { labels } from "../labels.js";

const DEFAULT_REASONS_LIMIT = 5;

/**
 * Render the unified "Why we think so" reasons section.
 *
 * @param {Object} riskData - { score, label, reasons }
 * @returns {HTMLElement}
 */
export function renderWhyWeThinkSo(riskData = {}) {
  const reasons = Array.isArray(riskData.reasons) ? riskData.reasons : [];
  const score = Math.round(riskData.score || 0);
  const label = riskData.label || "Low Risk";

  // Clean / No-threat State
  if (reasons.length === 0) {
    return createSafeElement("div", {
      className: "card card-elevated reasons-card reasons-clean-card",
      children: [
        createSafeElement("div", {
          className: "reasons-clean-header",
          children: [
            createSafeElement("div", {
              className: "reasons-clean-icon",
              attributes: { "aria-hidden": "true" },
              text: "🛡️",
            }),
            createSafeElement("div", {
              children: [
                createSafeElement("h2", {
                  className: "card-title",
                  text: labels.reasons.cleanTitle,
                }),
                createSafeElement("p", {
                  className: "text-muted",
                  style: "font-size: var(--text-sm); margin-top: var(--space-1);",
                  text: labels.reasons.cleanMessage,
                }),
              ],
            }),
          ],
        }),
      ],
    });
  }

  // Active Indicators State
  const riskCls = score >= 80 ? "badge-critical" : score >= 60 ? "badge-high" : "badge-suspicious";
  const container = createSafeElement("div", {
    className: "card card-elevated reasons-card",
  });

  // Card Header
  const header = createSafeElement("div", {
    className: "card-header",
    children: [
      createSafeElement("div", {
        children: [
          createSafeElement("h2", {
            className: "card-title",
            text: labels.reasons.title,
          }),
          createSafeElement("p", {
            className: "text-muted",
            style: "font-size: var(--text-xs); margin-top: 2px;",
            text: labels.reasons.subtitle,
          }),
        ],
      }),
      createSafeElement("span", {
        className: `badge ${riskCls}`,
        text: `${reasons.length} warning indicator${reasons.length === 1 ? "" : "s"}`,
      }),
    ],
  });
  container.appendChild(header);

  // Reasons List
  const list = createSafeElement("div", {
    className: "plain-reasons-list",
  });

  const topReasons = reasons.slice(0, DEFAULT_REASONS_LIMIT);
  const overflowReasons = reasons.slice(DEFAULT_REASONS_LIMIT);

  topReasons.forEach((r, idx) => {
    list.appendChild(_renderReasonItem(r, idx + 1));
  });

  if (overflowReasons.length > 0) {
    const overflowContainer = createSafeElement("div", {
      className: "reasons-overflow",
      style: "display: none; flex-direction: column; gap: var(--space-3);",
    });

    overflowReasons.forEach((r, idx) => {
      overflowContainer.appendChild(_renderReasonItem(r, topReasons.length + idx + 1));
    });

    list.appendChild(overflowContainer);

    // Toggle button for overflow
    const toggleBtn = createSafeElement("button", {
      className: "btn btn-secondary btn-toggle-reasons",
      attributes: { type: "button", "aria-expanded": "false" },
      style: "align-self: flex-start; margin-top: var(--space-2);",
      text: labels.reasons.showMore.replace("{count}", String(reasons.length)),
    });

    toggleBtn.addEventListener("click", () => {
      const isExpanded = toggleBtn.getAttribute("aria-expanded") === "true";
      if (isExpanded) {
        overflowContainer.style.display = "none";
        toggleBtn.setAttribute("aria-expanded", "false");
        toggleBtn.textContent = labels.reasons.showMore.replace("{count}", String(reasons.length));
      } else {
        overflowContainer.style.display = "flex";
        toggleBtn.setAttribute("aria-expanded", "true");
        toggleBtn.textContent = labels.reasons.showLess;
      }
    });

    list.appendChild(toggleBtn);
  }

  container.appendChild(list);
  return container;
}

/**
 * Render a single plain-language reason card with expandable explainer.
 */
function _renderReasonItem(rawReason, index) {
  const info = labels.translateReason(rawReason);
  const ptsMatch = String(rawReason).match(/^\+(\d+)\s*:/);
  const pts = ptsMatch ? ptsMatch[1] : null;

  return createSafeElement("div", {
    className: "plain-reason-item",
    children: [
      createSafeElement("div", {
        className: "reason-item-header",
        children: [
          createSafeElement("span", {
            className: "reason-item-icon",
            attributes: { "aria-hidden": "true" },
            text: "⚠️",
          }),
          createSafeElement("div", {
            className: "reason-item-body",
            children: [
              createSafeElement("div", {
                className: "reason-headline-row",
                children: [
                  createSafeElement("span", {
                    className: "reason-item-headline",
                    text: info.plain,
                  }),
                  pts
                    ? createSafeElement("span", {
                        className: "badge badge-neutral reason-pts-tag font-mono",
                        text: `+${pts} pts`,
                      })
                    : null,
                ].filter(Boolean),
              }),
              createSafeElement("p", {
                className: "reason-item-why",
                text: info.why,
              }),
              createSafeElement("details", {
                className: "reason-explainer",
                children: [
                  createSafeElement("summary", {
                    className: "reason-explainer-toggle",
                    text: labels.reasons.whatDoesThisMean,
                  }),
                  createSafeElement("div", {
                    className: "reason-explainer-content",
                    text: info.help,
                  }),
                ],
              }),
            ],
          }),
        ],
      }),
    ],
  });
}
