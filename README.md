# PhishGuard - Anti-Scam URL Checker

[![Chrome Web Store](https://img.shields.io/badge/Chrome%20Web%20Store-Install-4285F4?logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/phishguard-scam-phishing-checker/odbipahjojmphhmjgicnafkhiikjandb)
[![ClawHub](https://img.shields.io/badge/ClawHub-anti--scam--guard-red?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC40OCAxMC0xMFMxNy41MiAyIDEyIDJ6IiBmaWxsPSIjZmZmIi8+PC9zdmc+)](https://clawhub.ai/phishguard-niki/anti-scam-guard)
[![LINE Bot](https://img.shields.io/badge/LINE-@163hfjhz-00C300?logo=line&logoColor=white)](https://line.me/R/ti/p/@163hfjhz)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Blocklist Update](https://github.com/phishguard-niki/blocklist-data/actions/workflows/update-blocklist.yml/badge.svg)](https://github.com/phishguard-niki/blocklist-data/actions)

Detect phishing and scam URLs using heuristic analysis plus a blocklist of **2.5M+ known malicious domains** aggregated from **38 threat-intelligence feeds** (Taiwan 165, CERT.PL, PhishTank, OpenPhish, MetaMask, etc.). All domain matching runs locally — only the first letter of a domain is sent over the network to fetch the right shard.

## Three ways to use it

| | How | Best for |
|---|---|---|
| 🌐 **Chrome Extension** | [**Install from Chrome Web Store**](https://chromewebstore.google.com/detail/phishguard-scam-phishing-checker/odbipahjojmphhmjgicnafkhiikjandb) — one click | Chrome / Edge / Brave users — automatic page-level warnings, auto-updates |
| 🤖 **LINE Bot** | Add [`@163hfjhz`](https://line.me/R/ti/p/@163hfjhz) → paste suspicious links into the chat | Friends / parents / non-technical users — works on any phone, no install |
| 🧩 **OpenClaw Skill** | `clawhub install anti-scam-guard` | Inside any OpenClaw-compatible agent (Claude, etc.) |

## Features

- **Blocklist detection** — 2.5M+ domains from 38 feeds (Taiwan 165, CERT.PL, PhishTank, OpenPhish, MetaMask, etc.)
- **Heuristic analysis** — Detects suspicious patterns: homograph attacks, deep subdomains, risky TLDs, IP-based URLs, keyword matching
- **Google Safe Browsing** — Optional real-time lookup via GSB API
- **Multiple warning levels** — Full-page interstitial (must click to proceed), overlay banner, or subtle notification
- **Image scanner** — Scans page images for QR codes linking to scam sites
- **URL shortener alerts** — Warns when visiting shortened URLs (bit.ly, tinyurl, etc.)
- **Auto-updater** — Scheduled blocklist updates from 38 sources
- **Whitelist** — Built-in safe list for major legitimate sites (Google, Facebook, crypto exchanges, etc.)
- **i18n** — Traditional Chinese / English

## Installation

### Chrome / Edge / Brave (recommended)
**[Install from the Chrome Web Store](https://chromewebstore.google.com/detail/phishguard-scam-phishing-checker/odbipahjojmphhmjgicnafkhiikjandb)** — one click, auto-updates, no dev-mode required.

### Load unpacked (for development)
If you want to hack on the source or run a version ahead of the store release:
1. Clone this repo
2. Go to `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked** and select this folder (containing `manifest.json`)

### Safari
Safari Web Extension wrapper is planned but not yet available.

## Configuration

Click the extension icon → **Options** to configure:
- Language (繁體中文 / English)
- Google Safe Browsing API key (optional, for real-time detection)
- Image scanning on/off
- URL shortener warnings
- Custom blocklist entries

## Project Structure

```
PhishGuard/
├── manifest.json              # Extension manifest (MV3)
├── background.js              # Core detection engine
├── options.html / options.js  # Settings page
├── content/                   # Content scripts
│   ├── banner.js              # Warning banner overlay
│   ├── interstitial.js        # Full-page block screen
│   ├── imageScanner.js        # QR code / image scanner
│   └── overlay.js             # Subtle overlay notification
├── ui/                        # CSS styles
├── data/                      # Blocklist shards (generated)
├── assets/                    # Icons
├── anti-scam-extension-v042-auto/  # Auto-updater pipeline
│   ├── auto_update_v2.js      # Main update script
│   ├── config/sources.json    # 38 feed source definitions
│   └── test_sources.js        # Source availability tests
├── openclaw-skill/            # OpenClaw/ClawHub skill package
│   ├── SKILL.md               # Skill definition
│   ├── setup.sh               # Downloads blocklist from GitHub
│   └── lib/check_url.py       # Python URL checker
└── test_background.js         # 48 test cases
```

## Testing

```bash
node test_background.js
```

48 test cases covering: search engine false positives, legitimate site whitelisting, suspicious TLD detection, homograph attacks, deep subdomains, URL shorteners, and blocklist matching.

## OpenClaw Skill

PhishGuard is also available as an [OpenClaw](https://openclaw.com) skill for LINE chatbot integration:

```bash
clawhub install phishguard
```

## Blocklist Sources (38 feeds)

Phishing, malware, scam, and regulatory feeds including:
Taiwan 165, CERT.PL, PhishTank, OpenPhish, URLhaus, PhishStats, MetaMask, Spamhaus DBL, JPCERT, and more.

Full source list: `anti-scam-extension-v042-auto/config/sources.json`

## License

[MIT](LICENSE)
