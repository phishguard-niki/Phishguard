# PhishGuard - Anti-Scam Browser Extension v0.4.4

Browser extension that detects and blocks phishing/scam websites using a combination of heuristic analysis and a blocklist of 2.5M+ known malicious domains from 38 sources.

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

### Chrome / Edge / Brave
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select this folder (containing `manifest.json`)

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
