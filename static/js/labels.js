/**
 * PhishLens UI Text & Technical Glossary
 * Single source of truth for all user-facing strings, risk definitions, and tooltips.
 */

export const labels = {
  app: {
    title: "PhishLens — Email Threat Forensic Engine",
    subtitle: "Deep email inspection, relay origin tracing, and anomaly scoring",
    tagline: "Forensic Engine",
    disclaimer: "PhishLens is an educational forensic instrument. Threat scores and geolocation are probabilistic indicators, not definitive legal proof.",
    localAnalysisNotice: "Data analyzed locally",
  },

  theme: {
    toggleAria: "Toggle light and dark color themes",
    darkLabel: "Switch to light mode",
    lightLabel: "Switch to dark mode",
  },

  mask: {
    toggleLabel: "Mask personal data",
    tooltip: "Redacts sender and recipient email addresses and names in both the dashboard and exportable report.",
  },

  riskLevels: {
    low: {
      name: "Low Risk",
      badgeClass: "badge-low",
      description: "No significant malicious indicators or authentication failures detected.",
      icon: "shield-check",
    },
    suspicious: {
      name: "Suspicious",
      badgeClass: "badge-suspicious",
      description: "Anomalies or missing authentication detected. Exercise caution before trusting links.",
      icon: "alert-triangle",
    },
    high: {
      name: "High Risk",
      badgeClass: "badge-high",
      description: "Strong phishing signals, deceptive URLs, or sender domain mismatches identified.",
      icon: "alert-octagon",
    },
    critical: {
      name: "Critical",
      badgeClass: "badge-critical",
      description: "Severe threat detected. Multiple critical failures, active typosquatting, or known phishing signatures.",
      icon: "shield-alert",
    },
  },

  tabs: {
    upload: "Upload .EML File",
    paste: "Paste Raw Email Headers",
  },

  upload: {
    dropPrompt: "Drop your .eml email file here to scan",
    dropActive: "Release file to begin forensic analysis",
    browsePrompt: "or click to browse your filesystem",
    hint: "Accepts standard RFC 822 / MIME format (.eml) up to 25 MB",
    removeFile: "Remove selected file",
    scanButton: "Analyze Email",
    scanningButton: "Analyzing Telemetry...",
    loadSampleLegit: "Load Legitimate Sample",
    loadSamplePhish: "Load Phishing Sample",
  },

  paste: {
    placeholder: "Paste raw email headers or entire .eml message content here...\n\nExample:\nFrom: support@example.com\nTo: user@example.com\nSubject: Account Notification\nReceived: from mail.example.com ...",
    charCount: "{count} characters",
    scanButton: "Analyze Headers",
  },

  progressStages: [
    "Reading and parsing email structure...",
    "Extracting cryptographic signatures & headers...",
    "Validating SPF, DKIM, and DMARC records...",
    "Tracing MTA relay chain hops...",
    "Inspecting embedded URLs and domain age...",
    "Evaluating content with ML classifier...",
    "Aggregating evidence & computing forensic score...",
  ],

  errors: {
    noInput: "Please select an .eml file or paste email headers to analyze.",
    invalidFileType: "Invalid file format. Only .eml files are supported.",
    fileTooLarge: "File exceeds the maximum allowed size of {maxSize}.",
    emptyFile: "The selected file is empty.",
    networkError: "Unable to reach the analysis engine. Check your server connection and try again.",
    timeout: "Analysis request timed out. The server may be under high load.",
    serverError: "Analysis failed on the server. Please verify the email format.",
  },

  glossary: {
    spf: {
      term: "Sender Policy Framework (SPF)",
      explanation: "A DNS record specifying which IP addresses and mail servers are authorized to send email for a domain.",
    },
    dkim: {
      term: "DomainKeys Identified Mail (DKIM)",
      explanation: "A cryptographic digital signature in the email header verifying that the email was sent by the domain owner and not altered in transit.",
    },
    dmarc: {
      term: "DMARC",
      explanation: "Domain-based Message Authentication, Reporting, and Conformance. Instructs receivers how to handle emails that fail SPF or DKIM checks.",
    },
    mta: {
      term: "Mail Transfer Agent (MTA)",
      explanation: "A mail server along the delivery path that received, forwarded, and recorded a 'Received:' header.",
    },
    asn: {
      term: "Autonomous System Number (ASN)",
      explanation: "A unique identifier for a collection of IP routing prefixes operated by an internet service provider or hosting network.",
    },
    punycode: {
      term: "Punycode / IDN Homograph",
      explanation: "A representation of non-ASCII internationalized characters that attackers often use to visually mimic legitimate brand domains.",
    },
    typosquatting: {
      term: "Look-Alike / Typosquatting",
      explanation: "A registered domain intentionally similar to a known brand (e.g., paypa1.com vs paypal.com) to deceive recipients.",
    },
  },

  actions: {
    copy: "Copy to clipboard",
    copied: "Copied!",
    copyFailed: "Failed to copy",
    printReport: "Print / Save as PDF",
    downloadJson: "Export Raw JSON",
    reset: "Analyze Another Email",
    viewReport: "View Forensic Report",
  },
};
