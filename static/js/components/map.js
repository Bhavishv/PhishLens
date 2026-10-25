/**
 * PhishLens Origin Map & Structured Geolocation Table Component
 * Leaflet map wrapper with offline resilience, tile failure detection,
 * and a non-map accessible structured hop table alternative.
 */

import { createSafeElement, defangDomain } from "../defang.js";

let _activeMapInstance = null;

export function renderOriginMapAndTable(originData = {}) {
  const container = createSafeElement("div", {
    className: "map-section-wrapper",
  });

  const geo = originData.geolocation || {};
  const probableOrigin = geo.probable_origin || {};
  const allHops = geo.all_hops || [];
  const relayChain = originData.relay_chain || [];

  // 1. Map Card Container
  const mapCard = createSafeElement("div", {
    className: "card card-elevated map-card",
    children: [
      createSafeElement("div", {
        className: "card-header",
        children: [
          createSafeElement("span", {
            className: "card-title",
            text: "Geographic Origin Routing",
          }),
          createSafeElement("span", {
            className: "text-muted",
            style: "font-size: var(--text-xs);",
            text: "OpenStreetMap · Leaflet v1.9",
          }),
        ],
      }),
      // Leaflet Map Container
      createSafeElement("div", {
        className: "map-container-frame",
        children: [
          createSafeElement("div", {
            attributes: {
              id: "originMap",
              role: "region",
              "aria-label": "Geographic map showing email origin and MTA relay path",
            },
            style: "width: 100%; height: 340px; border-radius: var(--radius-md); background: var(--bg-sunken);",
          }),
        ],
      }),
    ],
  });

  container.appendChild(mapCard);

  // 2. Non-Map Structured Hop Table (Always rendered for accessibility & offline fallback)
  const tableCard = createSafeElement("div", {
    className: "card table-card",
    style: "margin-top: var(--space-4);",
    children: [
      createSafeElement("div", {
        className: "card-header",
        children: [
          createSafeElement("span", {
            className: "card-title",
            text: "Structured Hop Routing Telemetry",
          }),
          createSafeElement("span", {
            className: "text-muted",
            style: "font-size: var(--text-xs);",
            text: "Tabular Alternative",
          }),
        ],
      }),
      createSafeElement("div", {
        className: "table-responsive",
        children: [
          _renderHopTable(relayChain, allHops, probableOrigin),
        ],
      }),
    ],
  });

  container.appendChild(tableCard);

  // Lazy initialize Leaflet after container is attached to DOM
  setTimeout(() => {
    _initLeafletMap("originMap", probableOrigin, allHops);
  }, 100);

  return container;
}

function _renderHopTable(relayChain, allHops, probableOrigin) {
  const table = createSafeElement("table", {
    className: "telemetry-table",
    attributes: { "aria-label": "Structured hop routing data" },
  });

  // Table Head
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

  // Table Body
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
        <strong>Map Offline:</strong> Leaflet is operating in fallback mode. All relay hops are fully documented in the structured table below.
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

    // Draw routing dashed polyline if multiple hops have coordinates
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

    // React to theme changes to refresh map dimensions
    window.addEventListener("phishlens:theme-change", () => {
      if (_activeMapInstance) _activeMapInstance.invalidateSize();
    });
  } catch (err) {
    console.warn("[PhishLens] Map initialization failed, relying on structured table:", err);
  }
}
