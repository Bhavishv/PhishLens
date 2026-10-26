/**
 * PhishLens UI Text & Plain-Language Glossary
 * Single source of truth for all user-facing strings, Grade-8 risk definitions,
 * recommended action lists, onboarding guides, and plain-language translations.
 */

export const labels = {
  app: {
    title: "PhishLens — Email Safety Checker",
    subtitle: "Check if an email is safe, see who really sent it, and know what to do next.",
    tagline: "Email Safety Checker",
    badge: "Email Safety Checker",
    disclaimer: "PhishLens helps you spot email scams. Results and server locations are helpful estimates, not absolute legal proof.",
    localAnalysisNotice: "Your email is analyzed locally on this device",
    statusOnline: "Ready to check emails",
  },

  theme: {
    toggleAria: "Toggle light and dark color themes",
    darkLabel: "Switch to light mode",
    lightLabel: "Switch to dark mode",
  },

  mask: {
    toggleLabel: "Mask personal data",
    tooltip: "Hides sender and recipient email addresses and names in both the dashboard and exportable report.",
  },

  riskLevels: {
    low: {
      name: "Low Risk",
      badgeClass: "badge-low",
      headline: "This email looks safe.",
      sentence: "We didn't find any signs of a scam, spoofed sender, or dangerous links.",
      icon: "shield-check",
      actions: [
        "It is generally safe to read and interact with this email.",
        "Still exercise normal caution if the message asks for unexpected payments, gift cards, or passwords.",
      ],
    },
    suspicious: {
      name: "Suspicious",
      badgeClass: "badge-suspicious",
      headline: "Be careful with this email.",
      sentence: "Something doesn't look quite right. We found warning signs that warrant extra caution.",
      icon: "alert-triangle",
      actions: [
        "Do not click any links or download attachments until you verify who sent it.",
        "Do not reply to this message or send any personal details.",
        "If it claims to be from a company you use (like your bank), visit their official website directly in your browser instead of clicking links here.",
      ],
    },
    high: {
      name: "High Risk",
      badgeClass: "badge-high",
      headline: "This email is very likely a scam.",
      sentence: "We found strong evidence that this message is trying to trick or deceive you.",
      icon: "alert-octagon",
      actions: [
        "Do not click any links, open attachments, or reply to the sender.",
        "Do not share any passwords, account credentials, or payment details.",
        "Report this message to your company's IT or security team, or mark it as phishing in your email app.",
        "Delete the message once reported.",
      ],
    },
    critical: {
      name: "Critical Risk",
      badgeClass: "badge-critical",
      headline: "Dangerous scam detected.",
      sentence: "This email is an active phishing attempt using deceptive addresses or known scam techniques.",
      icon: "shield-alert",
      actions: [
        "Stop: Do not click any links, open any attachments, or reply.",
        "If you already clicked a link or entered a password, change that password immediately on the real website.",
        "Report this email to your organization's security team or email administrator right away.",
        "Permanently delete this email from your inbox and trash.",
      ],
    },
  },

  tabs: {
    upload: "Upload .eml File",
    paste: "Paste Email Text",
  },

  upload: {
    dropPrompt: "Drop your email file (.eml) here",
    dropActive: "Release file to check email safety",
    browsePrompt: "or click to select from your computer",
    hint: "Accepts .eml email files up to 25 MB",
    removeFile: "Remove selected file",
    scanButton: "Check Email Safety",
    scanningButton: "Checking Email...",
    sampleIntro: "Want to try an example first?",
    loadSampleLegit: "Clean Email Example",
    loadSamplePhish: "Scam Email Example",
  },

  emlHelp: {
    summary: "How to get a .eml file from your email app",
    clients: [
      {
        name: "Gmail",
        steps: [
          "Open the email in Gmail.",
          "Click the three vertical dots (More options) at the top right of the message.",
          "Select 'Download message' — your browser will save a .eml file.",
        ],
      },
      {
        name: "Outlook",
        steps: [
          "In Outlook Web: Open the email, click the three dots (...), and choose 'Download' or 'Save as'.",
          "In Outlook Desktop: Drag the email from your inbox directly to your desktop or folder, or select File ➔ Save As.",
        ],
      },
      {
        name: "Apple Mail",
        steps: [
          "Select the email in Apple Mail.",
          "Click 'File' in the top menu, then 'Save As...'",
          "Choose 'Raw Message Source' (.eml) and save.",
        ],
      },
      {
        name: "Thunderbird",
        steps: [
          "Select the email in Thunderbird.",
          "Click 'File' ➔ 'Save As' ➔ 'File...'",
          "Save as a .eml file.",
        ],
      },
    ],
  },

  paste: {
    placeholder: "Paste email headers or full email text here...\n\nExample:\nFrom: alerts@bank-security-support.com\nTo: user@example.com\nSubject: Urgent: Verify Account Credentials\nDate: Mon, 24 Oct 2026 12:00:00 +0000\nReceived: from unknown-relay.net (203.0.113.45) by mx.company.com ...",
    charCount: "{count} characters",
    scanButton: "Check Pasted Text",
  },

  progressStages: [
    "Reading the email...",
    "Checking who really sent it...",
    "Looking at the links and files...",
    "Tracing where it came from...",
    "Reviewing the message wording...",
    "Finalizing your safety report...",
  ],

  errors: {
    noInput: "Please select an .eml file or paste email text to check.",
    invalidFileType: "Invalid file format. Please upload a .eml email file.",
    fileTooLarge: "This file is larger than the maximum allowed size of {maxSize}.",
    emptyFile: "The selected file is empty.",
    networkError: "Unable to reach the safety checker. Please check your connection and try again.",
    timeout: "The check took too long to finish. The server might be busy. Please try again.",
    serverError: "Something went wrong while checking the email. Please make sure it's a valid email file.",
  },

  sections: {
    verdictTitle: "Is this email safe?",
    actionsTitle: "What you should do",
    reasonsTitle: "Why we think so",
    originTitle: "Where did it come from?",
    linksTitle: "Links and attachments in this email",
    analystTitle: "Technical details (for analysts)",
    analystSubtitle: "Raw headers, cryptographic records, server hops, and data hashes",
  },

  actions: {
    copy: "Copy",
    copied: "Copied!",
    copyFailed: "Failed to copy",
    printReport: "Print / Save PDF",
    downloadJson: "Export Raw JSON",
    reset: "Check Another Email",
    viewReport: "View Full Report",
    showMore: "Show all reasons ({count})",
    showLess: "Show top reasons",
    whatDoesThisMean: "What does this mean?",
  },

  reasons: {
    title: "Why we think so",
    subtitle: "Key factors flagged during email safety analysis",
    cleanTitle: "No suspicious indicators found",
    cleanMessage: "Sender authentication checks passed, the sender domain appears established, and no deceptive links or scam language were detected.",
    showMore: "Show all reasons ({count})",
    showLess: "Show top reasons",
    whatDoesThisMean: "What does this mean?",
  },

  origin: {
    title: "Where did it come from?",
    subtitle: "Origin mail server and network routing path",
    approxDisclaimer: "Server locations are estimates based on public network routing records, not physical GPS tracking of the sender.",
    likelyOrigin: "Probable Origin Server",
    location: "Estimated Location",
    network: "Network / ISP",
    hopsCount: "Server Hops",
    privateNetwork: "Internal / Private Network",
    unknownLocation: "Location could not be determined",
    summaryFormat: "Probably sent from a mail server in {location}",
    summaryPrivate: "Sent from an internal private network",
    singleHop: "1 server handled this message directly",
    multiHops: "{count} servers handled this message before delivery",
    copyIp: "Copy IP",
  },

  links: {
    title: "Links and attachments in this email",
    subtitle: "Neutralized links and attached files detected in this message",
    safetyNotice: "All links shown below are neutralized (defanged) and cannot be clicked to protect you from malicious websites.",
    suspiciousTitle: "Suspicious Links",
    cleanTitle: "Standard Links",
    attachmentsTitle: "Files attached to this email",
    noLinksOrAttachments: "No web links or attachments were found in this email.",
    noLinks: "No web links found in this email.",
    noAttachments: "No files attached to this email.",
    mismatchWarning: "The text in the email claimed to be: '{anchor}', but the link actually goes to:",
    copyUrl: "Copy Link",
    copyHash: "Copy Hash",
    riskyAttachmentWarning: "Warning: Executable files or scripts can run malicious software on your computer if opened.",
  },

  /**
   * Plain-language translation helper for findings.
   * Maps backend reasons and technical phrases to clear, Grade-8 explanations.
   */
  plainReasons: [
    {
      match: /SPF (failed|check returned|record not found|no SPF)/i,
      plain: "We couldn't confirm this email really came from the sender it claims.",
      why: "The sender's mail server wasn't authorized by the real domain owner.",
      help: "Companies publish a list of servers allowed to send their email (called SPF). When this check fails, someone may be pretending to be them.",
    },
    {
      match: /DKIM (failed|check returned|record not found|no DKIM)/i,
      plain: "The sender's digital signature is missing or altered.",
      why: "The message may have been modified or forged after being sent.",
      help: "Digital signatures (DKIM) verify that an email was really sent by the domain owner and wasn't altered in transit.",
    },
    {
      match: /DMARC (failed|check returned|record not found|no DMARC)/i,
      plain: "The sender's domain security rules rejected this message.",
      why: "The domain owner asked email providers to block or flag unauthorized mail.",
      help: "DMARC tells receiving servers how to handle emails that fail verification checks. A failure means the domain owner considers it suspicious.",
    },
    {
      match: /From domain .* differs from Return-Path/i,
      plain: "The bounce-back address doesn't match the sender address.",
      why: "If this email fails to deliver, the error message goes to a completely different place than the address shown to you.",
      help: "Scammers often put a legitimate company address in the 'From' field while routing delivery notices to their own server.",
    },
    {
      match: /Reply-To domain .* differs from From/i,
      plain: "Replies would go to a different address than the sender shown.",
      why: "If you click 'Reply', your message will be sent to someone else, not the sender you see on screen.",
      help: "This is a common scam technique: the email shows a familiar brand name, but replies go directly to the attacker.",
    },
    {
      match: /Message-ID domain .* differs from From/i,
      plain: "Technical tracking info shows this was created by a different mail server.",
      why: "The unique identifier on this message points to a server unrelated to the sender.",
      help: "Every mail server stamps a unique ID onto messages. An unrelated ID often indicates a disguised sender.",
    },
    {
      match: /Email text matches phishing patterns|phishing patterns|ML content classifier|phishing-like|Keyword fallback/i,
      plain: "The message uses common scam wording (such as urgent warnings or account threats).",
      why: "Scammers frequently create artificial urgency to panic you into acting without thinking.",
      help: "Legitimate organizations rarely threaten immediate account suspension or demand urgent action over email.",
    },
    {
      match: /newly registered|registered .* days ago/i,
      plain: "The sender's website was created very recently.",
      why: "Scam websites are often set up just days before an attack and taken down shortly after.",
      help: "Legitimate businesses usually use web domains that have been registered for years.",
    },
    {
      match: /lookalike|typosquatting|resembles/i,
      plain: "The web address imitates a well-known brand.",
      why: "Attackers register addresses with subtle misspellings (like replacing 'l' with '1') to trick you into trusting them.",
      help: "Always check spellings carefully. For example, 'paypa1.com' is not the real 'paypal.com'.",
    },
    {
      match: /IP address instead of domain|URL uses an IP address/i,
      plain: "A link in the email uses a raw IP address instead of a website name.",
      why: "Legitimate businesses use recognizable names (like 'bank.com'), not numbered IP addresses.",
      help: "Scammers use numerical IP addresses to conceal where the link really takes you.",
    },
    {
      match: /Anchor text|mismatched link|claims to link to|claims to go/i,
      plain: "A link claims to take you to one site, but actually leads elsewhere.",
      why: "The link text displayed in the email doesn't match the real destination address.",
      help: "This deceptive trick makes links appear safe until you click them. Always check destination URLs.",
    },
    {
      match: /suspicious TLD|suspicious top-level domain/i,
      plain: "A link uses an unusual or high-risk domain extension.",
      why: "Certain website extensions are heavily favored by attackers because they have minimal security oversight.",
      help: "Be cautious when links end in unfamiliar extensions instead of common ones like .com, .org, or official government domains.",
    },
    {
      match: /URL shortener|shortened link/i,
      plain: "A shortened link was used to hide its true destination.",
      why: "Link shortening services conceal the actual website address from view.",
      help: "Attackers use link shorteners so you cannot see the real destination before clicking.",
    },
    {
      match: /punycode|IDN encoding/i,
      plain: "Special character tricks are used in web or sender addresses.",
      why: "Characters from foreign alphabets that look identical to regular letters are used to spoof real brand names.",
      help: "This technique (known as an IDN homograph attack) creates domain names that look genuine to the human eye.",
    },
    {
      match: /missing Message-ID|missing Date|missing From/i,
      plain: "Standard email header information is missing.",
      why: "Legitimate mail servers generate these required headers automatically.",
      help: "Missing headers usually mean the email was generated using bulk-spamming scripts rather than standard mail clients.",
    },
    {
      match: /multiple From addresses/i,
      plain: "Multiple sender addresses were detected in the email.",
      why: "Standard emails only have one sender address.",
      help: "Spammers sometimes inject extra From addresses to confuse security software and trick users.",
    },
    {
      match: /future|in the future|inconsistent timestamp/i,
      plain: "The email timestamp does not match real time.",
      why: "The message claims to have been sent in the future or far in the past.",
      help: "Forged or manipulated timestamps are common indicators of automated spam tools.",
    },
  ],

  /**
   * Helper function to translate any raw backend reason into a plain-language explanation.
   */
  translateReason(rawReason) {
    if (!rawReason) {
      return {
        plain: "Warning indicator detected in email.",
        why: "An unusual pattern was found.",
        help: "Review the technical details below for more information.",
      };
    }

    // Strip "+10 : " or "+6 : " point prefix if present
    const cleaned = rawReason.replace(/^\+\d+\s*:\s*/, "").trim();

    for (const rule of labels.plainReasons) {
      if (rule.match.test(cleaned)) {
        return {
          plain: rule.plain,
          why: rule.why,
          help: rule.help,
        };
      }
    }

    // Fallback: Return clean sentence
    return {
      plain: cleaned,
      why: "This indicator was flagged by our safety checks.",
      help: "See the technical details section below for the complete header record.",
    };
  },

  /**
   * Helper to retrieve the full riskLevel config object for a given label string.
   */
  getRiskLevel(label = "") {
    const norm = String(label).toLowerCase().trim();
    if (norm.includes("critical")) return labels.riskLevels.critical;
    if (norm.includes("high")) return labels.riskLevels.high;
    if (norm.includes("suspicious")) return labels.riskLevels.suspicious;
    return labels.riskLevels.low;
  },
};
