/**
 * PhishLens Origin Map & Plain-Language Routing Section Component
 * Provides a plain-language summary sentence, honest approximation disclaimer,
 * responsive origin facts grid, simplified Leaflet map, and mobile-friendly hop cards.
 */

import { createSafeElement, defangDomain } from "../defang.js";
import { labels } from "../labels.js";

let _activeMapInstance = null;

/**
 * Render the complete "Where did it come from?" section.
 *
 * @param {Object} originData - Backend origin analysis object
 * @returns {HTMLElement}
 */
export function renderOriginSection(originData = {}) {
  const container = createSafeElement("div", {
    className: "card card-elevated origin-section-card",
  });

  const geo = originData.geolocation || {};
  const probableOrigin = geo.probable_origin || {};
  const allHops = geo.all_hops || [];
  const relayChain = originData.relay_chain || [];

  const locParts = [probableOrigin.city, probableOrigin.country].filter(Boolean);
  const locStr = locParts.join(", ");
  const isPrivate = Boolean(probableOrigin.is_private);

  let summarySentence = labels.origin.unknownLocation;
  if (isPrivate) {
    summarySentence = labels.origin.summaryPrivate;
  } else if (locStr) {
    summarySentence = labels.origin.summaryFormat.replace("{location}", locStr);
  }

  // 1. Header with Plain Summary Sentence & Disclaimer
  const header = createSafeElement("div", {
    className: "card-header origin-header",
    children: [
      createSafeElement("div", {
        children: [
          createSafeElement("h2", {
            className: "card-title",
            text: labels.origin.title,
          }),
          createSafeElement("p", {
            className: "origin-summary-sentence",
            text: summarySentence,
          }),
        ],
      }),
      createSafeElement("span", {
        className: `badge ${probableOrigin.ip ? "badge-accent" : "badge-neutral"}`,
        text: probableOrigin.ip ? "Origin Identified" : "Origin Estimated",
      }),
    ],
  });
  container.appendChild(header);

  // Honest Approximation Disclaimer
  const disclaimer = createSafeElement("p", {
    className: "origin-disclaimer text-muted",
    text: `ℹ️ ${labels.origin.approxDisclaimer}`,
  });
  container.appendChild(disclaimer);

  // 2. Responsive Origin Key Facts Grid (4 cards)
  const probableIp = probableOrigin.ip || originData.probable_origin_ip || "";
  const ispText = [probableOrigin.isp, probableOrigin.asn].filter(Boolean).join(" · ") || (isPrivate ? "Internal Organization Network" : "Standard Internet Relay");
  const hopsSummaryText = relayChain.length === 1
    ? labels.origin.singleHop
    : labels.origin.multiHops.replace("{count}", String(relayChain.length || 1));

  const factsGrid = createSafeElement("div", {
    className: "origin-facts-grid",
    children: [
      createSafeElement("div", {
        className: "origin-fact-item",
        children: [
          createSafeElement("span", { className: "origin-fact-label", text: labels.origin.likelyOrigin }),
          createSafeElement("div", {
            className: "origin-fact-value origin-fact-ip",
            children: [
              createSafeElement("code", {
                className: "font-mono font-bold",
                text: probableIp ? defangDomain(probableIp) : "Not recorded",
              }),
              probableIp
                ? createSafeElement("button", {
                    className: "btn-copy",
                    attributes: {
                      "data-copy-btn": "",
                      "data-copy-text": probableIp,
                      "aria-label": "Copy Origin IP",
                      title: labels.origin.copyIp,
                    },
                    children: [document.createTextNode("📋")],
                  })
                : null,
            ].filter(Boolean),
          }),
        ],
      }),
      createSafeElement("div", {
        className: "origin-fact-item",
        children: [
          createSafeElement("span", { className: "origin-fact-label", text: labels.origin.location }),
          createSafeElement("span", {
            className: "origin-fact-value font-semibold",
            text: locStr || (isPrivate ? labels.origin.privateNetwork : "Location Unresolved"),
          }),
        ],
      }),
      createSafeElement("div", {
        className: "origin-fact-item",
        children: [
          createSafeElement("span", { className: "origin-fact-label", text: labels.origin.network }),
          createSafeElement("span", {
            className: "origin-fact-value text-muted",
            style: "font-size: var(--text-xs);",
            text: ispText,
          }),
        ],
      }),
      createSafeElement("div", {
        className: "origin-fact-item",
        children: [
          createSafeElement("span", { className: "origin-fact-label", text: labels.origin.hopsCount }),
          createSafeElement("span", {
            className: "origin-fact-value",
            text: hopsSummaryText,
          }),
        ],
      }),
    ],
  });
  container.appendChild(factsGrid);

  // 3. Simplified Leaflet Map
  const mapFrame = createSafeElement("div", {
    className: "map-container-frame",
    style: "margin-top: var(--space-4);",
    children: [
      createSafeElement("div", {
        attributes: {
          id: "originMap",
          role: "region",
          "aria-label": "Geographic map showing email origin and MTA relay path",
        },
        style: "width: 100%; height: 280px; border-radius: var(--radius-md); background: var(--bg-sunken);",
      }),
    ],
  });
  container.appendChild(mapFrame);

  // 4. Responsive Relay Hop Cards (Mobile-friendly replacement for 6-column table)
  if (relayChain.length > 0) {
    const hopsSection = createSafeElement("div", {
      className: "origin-hops-section",
      style: "margin-top: var(--space-5);",
      children: [
        createSafeElement("h3", {
          className: "origin-hops-heading",
          text: `Mail Server Routing Path (${relayChain.length} server${relayChain.length === 1 ? "" : "s"})`,
        }),
        createSafeElement("div", {
          className: "origin-hops-cards-list",
          children: relayChain.map((hop, idx) => {
            const hopIp = hop.ip || "";
            const isProbable = hopIp && hopIp === probableIp;
            const geoInfo = allHops.find((h) => h.ip === hopIp) || {};
            const hopLoc = [geoInfo.city, geoInfo.country].filter(Boolean).join(", ") || (hop.is_private ? "Internal Network" : "Unresolved Location");

            return createSafeElement("div", {
              className: `origin-hop-card ${isProbable ? "origin-hop-card-probable" : ""}`,
              children: [
                createSafeElement("div", {
                  className: "origin-hop-card-top",
                  children: [
                    createSafeElement("div", {
                      className: "flex items-center gap-2",
                      children: [
                        createSafeElement("span", {
                          className: `badge ${isProbable ? "badge-critical" : "badge-neutral"} font-mono`,
                          text: `Hop #${hop.hop || idx + 1}`,
                        }),
                        isProbable
                          ? createSafeElement("span", {
                              className: "badge badge-critical",
                              text: "Probable Origin",
                            })
                          : null,
                      ].filter(Boolean),
                    }),
                    createSafeElement("span", {
                      className: "origin-hop-delay font-mono text-muted",
                      text: hop.delay_seconds !== null ? `+${Number(hop.delay_seconds).toFixed(1)}s delay` : "0.0s",
                    }),
                  ],
                }),
                createSafeElement("div", {
                  className: "origin-hop-card-body",
                  children: [
                    createSafeElement("div", {
                      className: "origin-hop-ip-row",
                      children: [
                        createSafeElement("span", { className: "text-muted", text: "Server IP: " }),
                        createSafeElement("code", {
                          className: "font-mono font-bold origin-hop-ip-code",
                          text: hopIp ? defangDomain(hopIp) : "No IP Recorded",
                        }),
                        hopIp
                          ? createSafeElement("button", {
                              className: "btn-copy",
                              attributes: {
                                "data-copy-btn": "",
                                "data-copy-text": hopIp,
                                "aria-label": `Copy IP ${hopIp}`,
                                title: labels.origin.copyIp,
                              },
                              children: [document.createTextNode("📋")],
                            })
                          : null,
                      ].filter(Boolean),
                    }),
                    createSafeElement("div", {
                      className: "origin-hop-location text-muted",
                      text: `📍 ${hopLoc}`,
                    }),
                    (hop.from_host || hop.by_host)
                      ? createSafeElement("div", {
                          className: "origin-hop-hosts text-muted",
                          style: "font-size: var(--text-xs); margin-top: 4px; word-break: break-all;",
                          text: `${hop.from_host ? defangDomain(hop.from_host) : "Unknown sender"} ➔ ${hop.by_host ? defangDomain(hop.by_host) : "Receiver"}`,
                        })
                      : null,
                  ].filter(Boolean),
                }),
              ],
            });
          }),
        }),
      ],
    });
    container.appendChild(hopsSection);
  }

  // Lazy initialize Leaflet map after DOM render
  setTimeout(() => {
    _initLeafletMap("originMap", probableOrigin, allHops);
  }, 120);

  return container;
}

/**
 * Render structured 6-column hop table (for Technical Details / Analyst Drawer).
 */
export function renderHopTable(relayChain = [], allHops = [], probableOrigin = {}) {
  const table = createSafeElement("table", {
    className: "telemetry-table",
    attributes: { "aria-label": "Structured hop routing data" },
  });

  const thead = createSafeElement("thead", {
    children: [
      createSafeElement("tr", {
        children: [
          createSafeElement("th", { text: "Hop" }),
          createSafeElement("th", { text: "Relay IP" }),
          createSafeElement("th", { text: "Location" }),
          createSafeElement("th", { text: "ISP / Network" }),
          createSafeElement("th", { text: "Transit Delay" }),
          createSafeElement("th", { text: "Classification" }),
        ],
      }),
    ],
  });
  table.appendChild(thead);

  const tbody = createSafeElement("tbody");

  if (!relayChain || relayChain.length === 0) {
    tbody.appendChild(
      createSafeElement("tr", {
        children: [
          createSafeElement("td", {
            attributes: { colspan: "6" },
            className: "text-center text-muted",
            text: "No relay hop telemetry available",
          }),
        ],
      })
    );
  } else {
    relayChain.forEach((hop, idx) => {
      const hopIp = hop.ip || "";
      const isProbable = hopIp && hopIp === probableOrigin.ip;
      const geoInfo = allHops.find((h) => h.ip === hopIp) || {};

      const locText = [geoInfo.city, geoInfo.country].filter(Boolean).join(", ") || (hop.is_private ? "Internal Network" : "Unresolved");
      const ispText = isProbable ? [probableOrigin.isp, probableOrigin.asn].filter(Boolean).join(" · ") : "Standard Relay";

      const tr = createSafeElement("tr", {
        className: isProbable ? "tr-origin-highlight" : "",
        children: [
          createSafeElement("td", {
            className: "font-mono font-bold",
            text: `#${hop.hop || idx + 1}`,
          }),
          createSafeElement("td", {
            children: [
              createSafeElement("code", { text: hopIp ? defangDomain(hopIp) : "N/A" }),
            ],
          }),
          createSafeElement("td", { text: locText }),
          createSafeElement("td", { className: "text-muted", text: ispText || "—" }),
          createSafeElement("td", {
            className: "font-mono",
            text: hop.delay_seconds !== null ? `+${Number(hop.delay_seconds).toFixed(1)}s` : "0.0s",
          }),
          createSafeElement("td", {
            children: [
              isProbable
                ? createSafeElement("span", { className: "badge badge-critical", text: "Probable Origin" })
                : createSafeElement("span", {
                    className: `badge ${hop.is_private ? "badge-neutral" : "badge-accent"}`,
                    text: hop.is_private ? "Private IP" : "Public Hop",
                  }),
            ],
          }),
        ],
      });

      tbody.appendChild(tr);
    });
  }

  table.appendChild(tbody);
  return table;
}

/**
 * Initialize Leaflet map safely.
 */
function _initLeafletMap(containerId, probableOrigin, allHops) {
  const mapEl = document.getElementById(containerId);
  if (!mapEl) return;

  if (_activeMapInstance) {
    try {
      _activeMapInstance.remove();
    } catch {}
    _activeMapInstance = null;
  }

  if (typeof window.L === "undefined") {
    mapEl.innerHTML = `
      <div class="alert alert-warning" style="margin: var(--space-4);">
        <strong>Map Offline:</strong> Leaflet is operating in fallback mode. Server routing details are displayed in the summary cards below.
      </div>
    `;
    return;
  }

  try {
    const defaultLat = probableOrigin.lat || (allHops[0] && allHops[0].lat) || 20.0;
    const defaultLon = probableOrigin.lon || (allHops[0] && allHops[0].lon) || 0.0;

    const map = window.L.map(containerId, {
      zoomControl: true,
      scrollWheelZoom: false,
    }).setView([defaultLat, defaultLon], probableOrigin.lat ? 5 : 2);

    window.L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a>',
    }).addTo(map);

    const latlngs = [];

    // Add Markers for all hops
    allHops.forEach((h, i) => {
      if (h.lat && h.lon) {
        const pt = [h.lat, h.lon];
        latlngs.push(pt);
        const isOrigin = h.ip === probableOrigin.ip;

        const marker = window.L.marker(pt).addTo(map);
        const cityStr = [h.city, h.country].filter(Boolean).join(", ");
        marker.bindPopup(`
          <strong>${isOrigin ? "⚠ Probable Origin Hop" : `Hop ${i + 1}`}</strong><br>
          IP: <code>${defangDomain(h.ip)}</code><br>
          Location: ${cityStr || "Unknown"}
        `);
      }
    });

    if (latlngs.length > 1) {
      window.L.polyline(latlngs, {
        color: "#7c83ff",
        weight: 3,
        dashArray: "6, 8",
        opacity: 0.85,
      }).addTo(map);

      try {
        const bounds = window.L.latLngBounds(latlngs);
        if (bounds.isValid()) {
          map.fitBounds(bounds, { padding: [30, 30] });
        }
      } catch {}
    }

    _activeMapInstance = map;

    window.addEventListener("phishlens:theme-change", () => {
      if (_activeMapInstance) _activeMapInstance.invalidateSize();
    });
  } catch (err) {
    console.warn("[PhishLens] Map initialization failed, relying on structured cards:", err);
  }
}

// Backwards-compatible export alias
export const renderOriginMapAndTable = renderOriginSection;
