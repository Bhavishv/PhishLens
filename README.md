# PhishLens — Email Threat Detection & Origin Tracing

> Upload an email. Find out if it's a scam, and where it really came from.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Backend-Flask-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Prototype-orange)

*PhishLens is a working title. Rename it to whatever you like.*

---

## Table of Contents

1. [About the Project](#1-about-the-project)
2. [The Problem (in Simple Words)](#2-the-problem-in-simple-words)
3. [Problem Statement and Scope](#3-problem-statement-and-scope)
4. [Our Solution](#4-our-solution)
5. [Features](#5-features)
6. [How It Works (Step by Step)](#6-how-it-works-step-by-step)
7. [System Architecture](#7-system-architecture)
8. [Tech Stack](#8-tech-stack)
9. [External APIs and Data Sources](#9-external-apis-and-data-sources)
10. [Datasets Used](#10-datasets-used)
11. [Risk Scoring Explained](#11-risk-scoring-explained)
12. [Project Structure](#12-project-structure)
13. [Installation](#13-installation)
14. [Usage](#14-usage)
15. [API Reference](#15-api-reference)
16. [Sample Output](#16-sample-output)
17. [Testing](#17-testing)
18. [Privacy, Legal and Ethics](#18-privacy-legal-and-ethics)
19. [Limitations](#19-limitations)
20. [Future Scope](#20-future-scope)
21. [2-Day Build Plan](#21-2-day-build-plan)
22. [Contributing](#22-contributing)
23. [License](#23-license)
24. [Acknowledgements](#24-acknowledgements)
25. [Disclaimer](#25-disclaimer)

---

## 1. About the Project

**PhishLens** is a web application that helps a person or a security analyst answer two questions about any suspicious email:

1. **Is this email dangerous?** (phishing, impersonation, fraud, or safe)
2. **Where did it actually come from?** (which servers handled it, and roughly which country and city the sender's server is in)

You upload an email file, and PhishLens shows a **risk score**, a **list of findings**, a **map of the email's journey**, and a **downloadable report**.

This project is inspired by **SIH 2026 Problem Statement 26106** ("AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"). It is an independent, personal project and is **not** an official Smart India Hackathon submission.

---

## 2. The Problem (in Simple Words)

Email is the easiest way for attackers to reach people. They send:

- fake invoices,
- messages pretending to be your boss or your bank,
- links to fake login pages that steal passwords.

These emails look very convincing because attackers use:

- **look-alike domains** (for example `paypa1.com` instead of `paypal.com`),
- **fake display names** (the name says "CEO", the address is something else),
- **hidden redirect links**,
- **relay servers** to hide where the email really started.

**What is wrong with today's tools?**
Most email security tools only *block* or *delete* bad emails using blacklists and fixed rules. They rarely help you *investigate*:

- Which servers did this email pass through?
- Is the sender's domain brand new?
- Where is the sending server located?
- Did the sender's identity pass authentication checks (SPF, DKIM, DMARC)?

PhishLens aims to fill that gap by **detecting** the threat and **explaining** it with forensic evidence.

---

## 3. Problem Statement and Scope

### Original Problem (Summary)
Build an AI-powered platform that can detect phishing, spoofed, impersonated and fraudulent emails; analyse the email's technical structure; trace its path across mail servers; estimate its origin location; and produce forensic intelligence to help investigations, while respecting privacy and legal standards.

### What the full problem statement asks for
The full statement is large. It includes real-time alerts, graph-based attribution, case management and more.

### What this project actually builds (realistic core)

A realistic core for a 2-day build:

- Upload a `.eml` file.
- Parse headers and check SPF/DKIM/DMARC results.
- Extract the relay chain and the first public IP, then geolocate it on a map.
- Run a simple phishing classifier, plus URL and lookalike-domain checks.
- Show a risk score and a downloadable report.

### Skipped for now (listed as Future Scope)
- Real-time alerts
- Full graph-based attribution
- Case management

---

## 4. Our Solution

PhishLens combines **five checks** into one easy result:

| # | Check | Plain-English meaning |
|---|-------|-----------------------|
| 1 | **Authentication check** | Did the email pass SPF, DKIM and DMARC? (These prove the sender is allowed to use that domain.) |
| 2 | **Header forensics** | Do the hidden technical fields contradict each other? (For example, the visible sender differs from the real return address.) |
| 3 | **Origin tracing + geolocation** | Follow the email's route through servers, find the first public IP, and place it on a map. |
| 4 | **Content analysis (ML)** | Does the text read like phishing? (urgency, threats, "verify your account", payment requests) |
| 5 | **URL and domain analysis** | Are the links suspicious? Is the sender domain a look-alike or very new? |

Each check produces findings and a score. The scores are combined into **one risk score from 0 to 100** with a clear label and an explanation of *why*.

---

## 5. Features

**Included (v1.0)**

- Drag-and-drop `.eml` upload (or paste raw headers)
- SPF / DKIM / DMARC result reading and verification
- Header anomaly detection (From vs Return-Path vs Reply-To mismatches, missing or odd headers)
- Relay chain (hop-by-hop) reconstruction
- Detection of the earliest public sender IP
- IP geolocation with country, region, city, ISP, ASN, VPN/proxy/hosting flags
- Interactive map showing the email's path
- ML phishing classifier trained on public email datasets
- URL checks (shorteners, raw-IP links, punycode, mismatched link text, and more)
- Look-alike domain detection (typos and character swaps)
- Domain age and registrar lookup (WHOIS/RDAP)
- Risk score (0–100) with a per-check breakdown
- Downloadable report (HTML, and optionally PDF)
- Optional masking of personal data in the report
- SHA-256 hash of the uploaded file for evidence integrity

**Not included yet** (see [Future Scope](#20-future-scope))

- Real-time mailbox monitoring and alerts
- Graph-based attribution of campaigns
- Case management

---

## 6. How It Works (Step by Step)

```
1. User uploads a .eml file
2. The file is hashed (SHA-256) so we can prove it was not changed
3. The email is parsed: headers, body text, links, attachments list
4. Authentication results are read (SPF / DKIM / DMARC)
5. Received headers are read from the bottom up (oldest hop first)
6. Private IPs are skipped; the first public IP is chosen as the "probable origin"
7. That IP is looked up for location, ISP, and proxy/hosting flags
8. The sender domain is checked: age, look-alike similarity
9. Links in the email are extracted and analysed
10. The ML model scores the email text
11. All signals are combined into one risk score + explanation
12. A dashboard and a downloadable report are produced
```

### Why we read "Received" headers from the bottom up
Every mail server that handles an email adds a `Received:` line at the **top**. So the **bottom-most** line is the oldest, which is closest to where the email started. PhishLens reads from the bottom to rebuild the journey in the right order.

### An important honesty note
Attackers can **forge** the lower `Received` lines. Only the lines added by servers *you trust* (usually the top ones) are fully reliable. PhishLens therefore reports the origin as a **probable** location with a **confidence label**, never as a certain fact.

---

## 7. System Architecture

### 7.1 High-Level View

```
 +----------------------+                      +-----------------------------+
 |        USER          |                      |        EXTERNAL SERVICES    |
 |  (Browser: HTML/JS)  |                      |                             |
 +----------+-----------+                      |  - ip-api.com (geolocation) |
            |                                  |  - GeoLite2 DB (offline)    |
            |  1. Upload .eml                  |  - WHOIS / RDAP (domains)   |
            v                                  |  - DNS (SPF/DKIM/DMARC)     |
 +----------+----------------------------+     +--------------^--------------+
 |             FLASK WEB SERVER          |                    |
 |  /            (upload page)           |                    |
 |  /analyze     (run analysis)          |                    |
 |  /report/<id> (download report)       |                    |
 +----------+----------------------------+                    |
            |                                                 |
            | 2. Pass raw email to analysis engine            |
            v                                                 |
 +----------+-------------------------------------------------+---------+
 |                       ANALYSIS ENGINE (Python)                       |
 |                                                                      |
 |  +--------------+   +----------------+   +------------------------+  |
 |  | Email Parser |-->| Header & Auth  |-->| Origin Tracer          |--+--> geolocation
 |  | (.eml → data)|   | Analyzer       |   | (relay chain + 1st IP) |  |
 |  +------+-------+   | SPF/DKIM/DMARC |   +------------------------+  |
 |         |           +----------------+                               |
 |         |                                                            |
 |         |           +----------------+   +------------------------+  |
 |         +---------->| URL & Domain   |-->| Domain Intelligence    |--+--> WHOIS/DNS
 |         |           | Analyzer       |   | (age, look-alikes)     |  |
 |         |           +----------------+   +------------------------+  |
 |         |                                                            |
 |         |           +----------------+                               |
 |         +---------->| NLP Classifier |   (TF-IDF + Logistic Reg.)    |
 |                     | (phishing prob)|                               |
 |                     +-------+--------+                               |
 |                             |                                        |
 |                             v                                        |
 |                   +---------+-----------+                            |
 |                   |  RISK SCORING ENGINE |  (weights → 0–100 score)  |
 |                   +---------+-----------+                            |
 +-----------------------------+----------------------------------------+
                               |
                               | 3. JSON result
                               v
 +-----------------------------+----------------------------------------+
 |                         RESULT LAYER                                  |
 |   Dashboard (score gauge, findings table, hop timeline, Leaflet map)  |
 |   Report Generator (Jinja2 → HTML → optional PDF)                     |
 +----------------------------------------------------------------------+
```

### 7.2 Data Flow (Simplified)

```
 .eml file
    |
    v
 [Hash + Parse] --> headers, body, links
    |
    +--> [Auth Check] -------------------> auth_score
    +--> [Header Anomalies] -------------> header_score
    +--> [Relay Chain → First Public IP]
    |         |
    |         +--> [Geolocation + Flags]
    |
    +--> [Sender Domain Intel] ----------> domain_score
    +--> [URL Analysis] -----------------> url_score
    +--> [ML Text Classifier] -----------> content_score
                                               |
                                               v
                              [Weighted Risk Score + Explanation]
                                               |
                                               v
                               [Dashboard + Downloadable Report]
```

### 7.3 Layers at a Glance

| Layer | Responsibility |
|-------|---------------|
| **Presentation** | Upload page, dashboard, map, report download (HTML/CSS/JS, Leaflet) |
| **Application** | Flask routes, input validation, file handling |
| **Analysis** | Parsing, authentication, tracing, ML, URL/domain checks, scoring |
| **Data / Integrations** | Public datasets, geolocation, WHOIS/DNS |

---

## 8. Tech Stack

| Area | Technology | Why it was chosen |
|------|-----------|-------------------|
| Language | **Python 3.10+** | Great libraries for email, networking and ML |
| Web framework | **Flask** | Small, simple, fast to build |
| Frontend | **HTML5, CSS3, JavaScript** | No heavy framework needed |
| Map | **Leaflet.js + OpenStreetMap tiles** | Free, no API key |
| Email parsing | Python `email` library (standard) | Reliable `.eml` handling |
| HTML/link parsing | `beautifulsoup4` | Extract links and visible text |
| SPF check | `pyspf` | Verify sender IP against SPF records |
| DKIM check | `dkimpy` | Verify the DKIM signature |
| DNS | `dnspython` | Look up SPF, DMARC, MX records |
| Domain info | `python-whois` or RDAP | Domain age and registrar |
| IP handling | `ipaddress` (standard) | Filter private and reserved IPs |
| ML | `scikit-learn` | TF-IDF + Logistic Regression |
| Text similarity | `rapidfuzz` | Fast look-alike domain matching |
| URL parsing | `tldextract` | Correctly split domain and suffix |
| Templates/Reports | `Jinja2` (+ `xhtml2pdf` optional) | Build HTML and PDF reports |
| HTTP client | `requests` | Call the geolocation API |
| Data handling | `pandas`, `numpy` | Prepare datasets |
| Testing | `pytest` | Simple automated tests |

---

## 9. External APIs and Data Sources

All of these have a **free option**.

| Purpose | Service | Key needed? | Notes |
|---------|---------|-------------|-------|
| IP geolocation (primary) | **ip-api.com** | No | Free tier ~45 requests/min. Returns country, city, ISP, ASN, lat/lon, proxy and hosting flags. Free tier uses **HTTP only**, so we call it from the **backend**, not the browser. |
| IP geolocation (backup, optional) | **FreeIPAPI** | No | Used as a fallback if the primary is unavailable. |
| IP geolocation (offline, optional) | **MaxMind GeoLite2** | Free account | Local database, no rate limit, and sender IPs never leave your machine. Good for privacy. |
| Map tiles | **OpenStreetMap** via **Leaflet** | No | Free, requires attribution (already built into Leaflet). |
| Domain registration info | **WHOIS / RDAP** | No | Used to get domain age. |
| Email authentication records | **Public DNS** | No | SPF, DKIM selector, and DMARC records. |

> Free-tier limits and terms can change. Check each provider's page before relying on them.

A single email has only a handful of hops, so rate limits are not a concern for this project.

---

## 10. Datasets Used

The project uses **publicly available email corpora** that can be downloaded directly, with no login or approval needed. Please check each source for its current terms and availability.

| Dataset | Role in this project | Where to get it |
|---------|---------------------|-----------------|
| **Nazario Phishing Corpus** | Real **phishing** emails (label = phishing) | `https://monkey.org/~jose/phishing/` |
| **Apache SpamAssassin Public Corpus** (`easy_ham`, `hard_ham`) | Real **legitimate** emails (label = legit) | `https://spamassassin.apache.org/old/publiccorpus/` |
| **Enron Email Dataset (CMU)** | Extra **legitimate** emails (sample a few thousand) | `https://www.cs.cmu.edu/~enron/` |

### How we use them
1. Download the files into `data/raw/`.
2. Read each email and keep the **subject + body text**.
3. Label phishing as `1` and legitimate as `0`.
4. Balance the classes (use roughly equal counts).
5. Split into training (80%) and testing (20%).
6. Train a TF-IDF + Logistic Regression model.

### Dataset caveats (please read)
- These datasets are **older** (roughly 2000s–2010s). Modern AI-written phishing may look different, so accuracy on today's emails will be lower. This is mentioned openly under [Limitations](#19-limitations).
- Some of these emails contain real names and addresses. **Do not redistribute the raw data**; keep it out of the repository. Only the trained model file is shipped.
- **Do not use SpamAssassin "spam" as phishing.** Spam and phishing are different. Use it, if at all, as an optional "suspicious" class.

---

## 11. Risk Scoring Explained

Each check gives a sub-score. The final score is a weighted sum out of **100**.

| Check | Max Points | What raises the score |
|-------|-----------:|-----------------------|
| Authentication | 25 | SPF fail, DKIM fail or missing, DMARC fail or missing |
| Header anomalies | 20 | From ≠ Return-Path, Reply-To points elsewhere, Message-ID domain mismatch, missing standard headers |
| Content (ML) | 25 | High phishing probability from the classifier |
| URLs | 15 | Shortened links, raw-IP links, punycode, text/link mismatch, too many subdomains, `@` in URL |
| Sender domain | 15 | Domain registered very recently, look-alike of a well-known brand |
| **Total** | **100** | |

### Result Labels

| Score | Label | Meaning |
|------:|-------|---------|
| 0–29 | 🟢 **Low Risk** | Likely legitimate |
| 30–59 | 🟡 **Suspicious** | Be careful, review the findings |
| 60–79 | 🟠 **High Risk** | Likely phishing or fraud |
| 80–100 | 🔴 **Critical** | Almost certainly malicious |

### Why it is explainable
Every point added to the score comes with a short reason, for example:
> "+10: DMARC check failed for the sender domain."
> "+8: Sender domain was registered 3 days ago."

This helps a human understand the result instead of just trusting a number.

*The weights above are a starting point. You can tune them in `config.py`.*

---

## 12. Project Structure

```
PhishLens/
├── app.py                     # Flask entry point
├── config.py                  # Weights, thresholds, API settings
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── analyzer/                  # The analysis engine
│   ├── __init__.py
│   ├── parser.py              # .eml → headers, body, links
│   ├── auth_checker.py        # SPF / DKIM / DMARC
│   ├── header_analyzer.py     # Mismatch and anomaly detection
│   ├── origin_tracer.py       # Relay chain + first public IP
│   ├── geolocator.py          # ip-api / FreeIPAPI / GeoLite2
│   ├── domain_intel.py        # WHOIS age, look-alike domains
│   ├── url_analyzer.py        # Link checks
│   ├── classifier.py          # Load model + predict phishing probability
│   ├── scorer.py              # Combine everything into 0–100
│   └── report.py              # Build HTML / PDF report
│
├── ml/
│   ├── prepare_data.py        # Read datasets, label, clean
│   ├── train.py               # Train and save the model
│   └── model/
│       └── phishing_model.joblib
│
├── data/
│   ├── raw/                   # Downloaded datasets (NOT committed)
│   ├── processed/
│   └── brands.txt             # Brand list for look-alike checks
│
├── templates/
│   ├── index.html             # Upload page
│   ├── result.html            # Dashboard
│   └── report_template.html   # Report layout
│
├── static/
│   ├── css/style.css
│   └── js/
│       ├── main.js            # Upload and UI logic
│       └── map.js             # Leaflet map drawing
│
├── samples/                   # Safe sample .eml files for demo/testing
│   ├── legit_sample.eml
│   └── phishing_sample.eml
│
└── tests/
    ├── test_parser.py
    ├── test_origin_tracer.py
    ├── test_url_analyzer.py
    └── test_scorer.py
```

---

## 13. Installation

### Prerequisites
- Python **3.10 or newer**
- `pip`
- Internet access (for geolocation, WHOIS and DNS lookups)
- Git (optional)

### Steps

```bash
# 1. Get the code
git clone https://github.com/<your-username>/PhishLens.git
cd PhishLens

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
#   Windows:
venv\Scripts\activate
#   macOS / Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### Suggested `requirements.txt`

```
flask
beautifulsoup4
dnspython
pyspf
dkimpy
python-whois
tldextract
rapidfuzz
requests
scikit-learn
pandas
numpy
joblib
jinja2
xhtml2pdf
pytest
```

### Train the Model (one time)

```bash
# Download the datasets into data/raw/ first (see Section 10)
python ml/prepare_data.py
python ml/train.py
```
This creates `ml/model/phishing_model.joblib`.

### Run the App

```bash
python app.py
```
Open your browser at **http://127.0.0.1:5000**

---

## 14. Usage

1. Open the website.
2. **Drag and drop** a `.eml` file (or paste the raw headers).
3. Click **Analyze**.
4. Review the dashboard:
   - **Risk gauge:** overall score and label
   - **Findings table:** each check, result and reason
   - **Relay timeline:** hop-by-hop path of the email
   - **Map:** the probable origin and route
5. Click **Download Report** to save the full result.
6. Optionally switch on **Mask personal data** before downloading.

### How to get a `.eml` file
- **Gmail:** open the email → ⋮ menu → *Download message*
- **Outlook (web):** open the email → ⋯ → *View* → *View message source* (save as `.eml`)
- **Thunderbird:** right-click the email → *Save As…*

> Always test with your own or sample emails. Never upload someone else's private email.

---

## 15. API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Upload page |
| POST | `/analyze` | Upload a `.eml` file (form field `file`) or raw headers (`raw`). Returns JSON. |
| GET | `/report/<id>` | Download the report for an analysis |
| GET | `/health` | Simple "is the server running" check |

**Example (command line):**
```bash
curl -X POST -F "file=@samples/phishing_sample.eml" http://127.0.0.1:5000/analyze
```

---

## 16. Sample Output

```json
{
  "file_sha256": "a3f5...c91e",
  "risk": {
    "score": 82,
    "label": "Critical",
    "breakdown": {
      "authentication": 22,
      "header_anomalies": 16,
      "content_ml": 21,
      "urls": 12,
      "sender_domain": 11
    },
    "reasons": [
      "SPF failed for sender domain",
      "DMARC policy not found",
      "Reply-To differs from From address",
      "Email text strongly matches phishing patterns (0.93)",
      "Link text shows 'paypal.com' but points to a different site",
      "Sender domain registered 3 days ago"
    ]
  },
  "origin": {
    "probable_ip": "203.0.113.45",
    "confidence": "Medium",
    "location": {
      "country": "Example Country",
      "city": "Example City",
      "isp": "Example Hosting Ltd",
      "lat": 12.97,
      "lon": 77.59,
      "is_proxy": false,
      "is_hosting": true
    }
  },
  "relay_chain": [
    { "hop": 1, "from": "unknown-host", "ip": "203.0.113.45", "timestamp": "..." },
    { "hop": 2, "from": "mail.relay.example", "ip": "198.51.100.7", "timestamp": "..." }
  ]
}
```
*(All values above are placeholders.)*

---

## 17. Testing

```bash
pytest tests/
```

What we test:
- Parser correctly reads headers and links from sample emails
- Private IPs (10.x, 192.168.x, 172.16–31.x) are skipped
- Relay chain order is correct
- Look-alike detection flags `paypa1.com` but not `paypal.com`
- Scoring never exceeds 100 and labels match thresholds

**Manual demo test:** run the two sample emails in `samples/`. The phishing sample should score high, and the legitimate sample should score low.

---

## 18. Privacy, Legal and Ethics

- **Local-first:** uploaded emails are processed in memory and **not stored** by default.
- **Evidence integrity:** every upload is hashed (SHA-256) and the hash appears in the report.
- **Masking:** optional masking of email addresses and names in the report.
- **Third-party calls:** only IP addresses and domain names are sent to external lookup services, never the email body. For maximum privacy, use the offline GeoLite2 database.
- **Use responsibly:** analyse only emails you own or have permission to analyse.
- **No accusations:** the tool gives *probable* indicators, not proof of identity. Do not use its output alone to accuse anyone.

---

## 19. Limitations

Being honest about limits makes the tool more trustworthy:

- **IP geolocation is approximate.** It is usually reliable at country level and rough at city level.
- **Forged headers:** attackers can fake lower `Received` lines, so origin is a *probable* estimate.
- **Webmail senders:** emails from Gmail, Outlook and similar services show the provider's server, not the person's own device.
- **VPN/Tor/proxy:** these hide the true source. We flag them but cannot see through them.
- **Older training data:** public phishing datasets are dated, so very modern or AI-written phishing may be missed.
- **No attachment scanning:** v1 lists attachments but does not scan them for malware.
- **Authentication checks need the original email:** if the message was edited or forwarded, DKIM may fail even for legitimate email.
- **Free API limits:** lookups may be slow or limited at times.

---

## 20. Future Scope

These are parts of the full problem statement that were intentionally left out of v1:

- 🔔 **Real-time alerts** by connecting to a mailbox (IMAP) or mail gateway
- 🕸️ **Graph-based attribution:** link domains, IPs and aliases into campaign graphs
- 🗂️ **Case management:** group related emails into searchable cases
- 🧠 **Better models:** transformer-based classifiers trained on modern phishing
- 📎 **Attachment analysis:** hashes, reputation checks, safe sandboxing
- 🧾 **Threat-intel feeds:** check IPs/domains against free community blocklists
- 🔐 **User accounts, audit logs and chain-of-custody records**
- 🌍 **Multi-language** phishing detection
- 🧩 **Browser or mail-client plugin** for one-click analysis

---

## 21. 2-Day Build Plan

**Day 1: Backend**
| Time block | Task |
|-----------|------|
| Morning | Project setup, `.eml` parser, hashing |
| Midday | Auth reading (SPF/DKIM/DMARC), header anomaly checks |
| Afternoon | Relay chain, first public IP, geolocation |
| Evening | URL and look-alike domain checks, train the ML model, scoring engine |

**Day 2: Website and polish**
| Time block | Task |
|-----------|------|
| Morning | Flask routes, upload page, result dashboard |
| Midday | Leaflet map, hop timeline, risk gauge |
| Afternoon | Report export, data masking toggle |
| Evening | Tests, sample emails, README, screenshots, demo run |

---

## 22. Contributing

Contributions are welcome.

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

Please keep code readable, add tests for new features, and never commit real personal emails.

---

## 23. License

This project is released under the **MIT License**. See the `LICENSE` file for details.

Third-party datasets, libraries and APIs keep their own licenses and terms.

---

## 24. Acknowledgements

- Smart India Hackathon 2026 Problem Statement 26106, for the idea
- Jose Nazario, for the public phishing corpus
- Apache SpamAssassin project, for the public mail corpus
- CMU / Enron email dataset
- ip-api.com and FreeIPAPI, for free geolocation lookups
- OpenStreetMap contributors and the Leaflet project
- The open-source Python community

---

## 25. Disclaimer

PhishLens is an **educational prototype**. Its results are indicators, not legal evidence or proof of identity. The authors are not responsible for decisions made based on its output. Always verify important findings with a qualified security professional.