/**
 * PhishLens Aperture Lens Risk Gauge Component
 * Generates an SVG circular optical aperture meter with concentric focus ticks,
 * animated stroke offset, score display, and category breakdown progress bars.
 */

import { createSafeElement } from "../defang.js";

const GAUGE_RADIUS = 76;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS; // ~477.52

/**
 * Map threat score to semantic theme token color.
 */
function getRiskColor(score) {
  if (score <= 29) return "var(--risk-low)";
  if (score <= 59) return "var(--risk-suspicious)";
  if (score <= 79) return "var(--risk-high)";
  return "var(--risk-critical)";
}

/**
 * Render the complete Aperture Gauge & Breakdown card.
 *
 * @param {Object} riskData - { score, label, breakdown, reasons }
 * @param {Object} [weights] - Category maximum points from config
 * @param {Object} [options] - Optional render flags (e.g. showBreakdown)
 * @returns {HTMLElement}
 */
export function renderRiskGauge(riskData = {}, weights = {}, options = {}) {
  const score = Math.max(0, Math.min(100, Math.round(riskData.score || 0)));
  const label = riskData.label || "Low Risk";
  const breakdown = riskData.breakdown || {};
  const strokeColor = getRiskColor(score);

  // Compute stroke dashoffset: 0 = full, circumference = empty
  const strokeOffset = GAUGE_CIRCUMFERENCE - (score / 100) * GAUGE_CIRCUMFERENCE;

  const container = createSafeElement("div", {
    className: "gauge-card card card-elevated",
  });

  // SVG Gauge Container
  const svgWrapper = createSafeElement("div", {
    className: "gauge-svg-wrapper",
  });

  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", "0 0 200 200");
  svg.setAttribute("class", "aperture-gauge-svg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Threat Score: ${score} out of 100, rated as ${label}`);

  // 1. Concentric Background Track Ring
  const trackCircle = document.createElementNS(svgNS, "circle");
  trackCircle.setAttribute("cx", "100");
  trackCircle.setAttribute("cy", "100");
  trackCircle.setAttribute("r", String(GAUGE_RADIUS));
  trackCircle.setAttribute("class", "gauge-track");

  // 2. Decorative Aperture Ticks (Optical Lens motif)
  const ticksGroup = document.createElementNS(svgNS, "g");
  ticksGroup.setAttribute("class", "gauge-ticks");
  for (let angle = 0; angle < 360; angle += 30) {
    const tick = document.createElementNS(svgNS, "line");
    const rad = (angle * Math.PI) / 180;
    const x1 = 100 + 64 * Math.cos(rad);
    const y1 = 100 + 64 * Math.sin(rad);
    const x2 = 100 + 70 * Math.cos(rad);
    const y2 = 100 + 70 * Math.sin(rad);
    tick.setAttribute("x1", x1.toFixed(1));
    tick.setAttribute("y1", y1.toFixed(1));
    tick.setAttribute("x2", x2.toFixed(1));
    tick.setAttribute("y2", y2.toFixed(1));
    ticksGroup.appendChild(tick);
  }

  // 3. Animated Progress Ring
  const progressCircle = document.createElementNS(svgNS, "circle");
  progressCircle.setAttribute("cx", "100");
  progressCircle.setAttribute("cy", "100");
  progressCircle.setAttribute("r", String(GAUGE_RADIUS));
  progressCircle.setAttribute("class", "gauge-progress");
  progressCircle.style.stroke = strokeColor;
  progressCircle.style.strokeDasharray = `${GAUGE_CIRCUMFERENCE}`;
  progressCircle.style.strokeDashoffset = `${strokeOffset}`;

  // 4. Center Numeric Score Text
  const scoreText = document.createElementNS(svgNS, "text");
  scoreText.setAttribute("x", "100");
  scoreText.setAttribute("y", "98");
  scoreText.setAttribute("class", "gauge-score-text");
  scoreText.textContent = String(score);

  // 5. Score Suffix (/100)
  const maxText = document.createElementNS(svgNS, "text");
  maxText.setAttribute("x", "100");
  maxText.setAttribute("y", "120");
  maxText.setAttribute("class", "gauge-max-text");
  maxText.textContent = "OUT OF 100";

  svg.appendChild(trackCircle);
  svg.appendChild(ticksGroup);
  svg.appendChild(progressCircle);
  svg.appendChild(scoreText);
  svg.appendChild(maxText);

  svgWrapper.appendChild(svg);
  container.appendChild(svgWrapper);

  // Verdict Badge
  const badgeClass = `badge-${label.toLowerCase().replace(" risk", "").replace(" ", "-")}`;
  const verdictPill = createSafeElement("div", {
    className: "text-center",
    style: "margin-bottom: var(--space-4);",
    children: [
      createSafeElement("span", {
        className: `badge ${badgeClass}`,
        style: "font-size: var(--text-sm); padding: var(--space-1) var(--space-4);",
        children: [
          createSafeElement("span", { className: "badge-dot" }),
          document.createTextNode(`Verdict: ${label}`),
        ],
      }),
    ],
  });
  container.appendChild(verdictPill);

  if (options.showBreakdown) {
    container.appendChild(renderCategoryBreakdown(breakdown, weights, strokeColor));
  }

  return container;
}

/**
 * Render Category Breakdown Progress Bars (for Analyst Details).
 */
export function renderCategoryBreakdown(breakdown = {}, weights = {}, strokeColor = "var(--accent-lens)") {
  const breakdownContainer = createSafeElement("div", {
    className: "gauge-breakdown",
  });

  const categories = [
    { key: "authentication", label: "Authentication", max: weights.authentication || 25 },
    { key: "header_anomalies", label: "Header Anomalies", max: weights.header_anomalies || 20 },
    { key: "content_ml", label: "Content ML", max: weights.content_ml || 25 },
    { key: "urls", label: "Deceptive URLs", max: weights.urls || 15 },
    { key: "sender_domain", label: "Sender Domain", max: weights.sender_domain || 15 },
  ];

  for (const cat of categories) {
    const catScore = breakdown[cat.key] || 0;
    const catPct = Math.min(100, Math.round((catScore / cat.max) * 100));

    const itemEl = createSafeElement("div", {
      className: "breakdown-item",
      children: [
        createSafeElement("div", {
          className: "breakdown-header",
          children: [
            createSafeElement("span", { className: "breakdown-label", text: cat.label }),
            createSafeElement("span", {
              className: "breakdown-val font-mono",
              text: `${catScore} / ${cat.max} pts`,
            }),
          ],
        }),
        createSafeElement("div", {
          className: "breakdown-track",
          children: [
            createSafeElement("div", {
              className: "breakdown-fill",
              style: `width: ${catPct}%; background-color: ${catScore > 0 ? strokeColor : "var(--border-strong)"};`,
            }),
          ],
        }),
      ],
    });

    breakdownContainer.appendChild(itemEl);
  }

  return breakdownContainer;
}
