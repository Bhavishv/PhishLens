/**
 * PhishLens MTA Relay Hop Timeline Component
 * Renders an ordered visual chain of mail servers (hops) from sender origin to receiver,
 * showing delays, server names, IP addresses, and private IP exclusions.
 */

import { createSafeElement, defangDomain } from "../defang.js";

export function renderHopTimeline(originData = {}) {
  const chain = originData.relay_chain || [];
  const probableIp = originData.probable_origin_ip;
  const confidence = originData.confidence || "unknown";
  const confidenceReasons = originData.confidence_reasons || [];

  const container = createSafeElement("div", {
    className: "timeline-container",
  });

  // 1. Origin Verdict Banner
  const originBanner = createSafeElement("div", {
    className: "card card-elevated origin-summary-card",
    children: [
      createSafeElement("div", {
        className: "card-header",
        children: [
          createSafeElement("span", {
            className: "card-title",
            children: [
              document.createTextNode("Probable Origin IP: "),
              createSafeElement("code", {
                className: "font-mono font-bold text-accent",
                style: "font-size: var(--text-md); margin-left: var(--space-2);",
                text: probableIp ? defangDomain(probableIp) : "Undetermined",
              }),
            ],
          }),
          createSafeElement("span", {
            className: `badge badge-${confidence === "high" ? "low" : confidence === "medium" ? "suspicious" : "neutral"}`,
            text: `Confidence: ${confidence.toUpperCase()}`,
          }),
        ],
      }),
      createSafeElement("div", {
        className: "origin-reasons-list",
        children: [
          createSafeElement("p", {
            className: "text-muted",
            style: "font-size: var(--text-sm); margin-bottom: var(--space-2);",
            text: "Forensic Analysis Rationale:",
          }),
          createSafeElement("ul", {
            style: "padding-left: var(--space-4); font-size: var(--text-sm); color: var(--text-muted);",
            children: confidenceReasons.map((reason) =>
              createSafeElement("li", { text: reason })
            ),
          }),
        ],
      }),
      createSafeElement("div", {
        className: "alert alert-info",
        style: "margin-top: var(--space-3); margin-bottom: 0; font-size: var(--text-xs);",
        text: "⚠ Forensics Notice: Origin is calculated from the earliest trusted public MTA hop. Received headers can be spoofed by initial senders prior to reaching legitimate relay servers.",
      }),
    ],
  });
  container.appendChild(originBanner);

  // 2. Timeline Chain Cards
  if (!chain || chain.length === 0) {
    container.appendChild(
      createSafeElement("div", {
        className: "alert alert-warning",
        style: "margin-top: var(--space-4);",
        text: "No valid Received: headers found to construct an MTA relay chain.",
      })
    );
    return container;
  }

  const timelineList = createSafeElement("div", {
    className: "hop-timeline",
  });

  chain.forEach((hop, idx) => {
    const isProbable = hop.ip && hop.ip === probableIp;
    const isPrivate = Boolean(hop.is_private);

    const hopCard = createSafeElement("div", {
      className: `hop-node ${isProbable ? "hop-node-origin" : ""}`,
      children: [
        // Numbered badge
        createSafeElement("div", {
          className: "hop-badge",
          text: `Hop ${hop.hop || idx + 1}`,
        }),
        // Hop Card Body
        createSafeElement("div", {
          className: "card hop-card-content",
          children: [
            createSafeElement("div", {
              className: "hop-header",
              children: [
                createSafeElement("div", {
                  className: "hop-title",
                  children: [
                    createSafeElement("span", {
                      className: "font-bold",
                      text: hop.from_host ? defangDomain(hop.from_host) : "Unknown Sender Host",
                    }),
                    createSafeElement("span", { className: "text-muted", text: " ➔ " }),
                    createSafeElement("span", {
                      text: hop.by_host ? defangDomain(hop.by_host) : "Receiving Server",
                    }),
                  ],
                }),
                createSafeElement("div", {
                  className: "hop-tags",
                  children: [
                    isProbable
                      ? createSafeElement("span", { className: "badge badge-critical", text: "Probable Origin" })
                      : null,
                    createSafeElement("span", {
                      className: `badge ${isPrivate ? "badge-neutral" : "badge-accent"}`,
                      text: isPrivate ? "Private / Internal IP" : "Public Relay",
                    }),
                  ].filter(Boolean),
                }),
              ],
            }),

            // IP & Timing Details
            createSafeElement("div", {
              className: "hop-meta flex items-center justify-between",
              style: "margin-top: var(--space-2); font-size: var(--text-xs); color: var(--text-muted); flex-wrap: wrap; gap: var(--space-2);",
              children: [
                createSafeElement("div", {
                  className: "flex items-center gap-2",
                  children: [
                    createSafeElement("span", { text: "Relay IP:" }),
                    createSafeElement("code", {
                      className: "font-mono font-bold",
                      text: hop.ip ? defangDomain(hop.ip) : "No IP recorded",
                    }),
                    hop.ip
                      ? createSafeElement("button", {
                          className: "btn-copy",
                          attributes: {
                            "data-copy-btn": "",
                            "data-copy-text": hop.ip,
                            "aria-label": `Copy IP ${hop.ip}`,
                            title: "Copy IP",
                          },
                          children: [
                            document.createTextNode("📋"),
                          ],
                        })
                      : null,
                  ].filter(Boolean),
                }),
                createSafeElement("div", {
                  className: "flex items-center gap-3",
                  children: [
                    hop.delay_seconds !== null && hop.delay_seconds !== undefined
                      ? createSafeElement("span", {
                          className: "font-mono",
                          text: `Transit Delay: +${Number(hop.delay_seconds).toFixed(1)}s`,
                        })
                      : null,
                    hop.timestamp
                      ? createSafeElement("span", { text: `Time: ${hop.timestamp}` })
                      : null,
                  ].filter(Boolean),
                }),
              ],
            }),
          ],
        }),
      ],
    });

    timelineList.appendChild(hopCard);
  });

  container.appendChild(timelineList);
  return container;
}
