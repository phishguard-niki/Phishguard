# PhishGuard Privacy Policy

**Effective date:** 2026-06-18
**Extension version:** 0.5.0+

## TL;DR

PhishGuard runs entirely in your browser. We do **not** collect, store, transmit, sell, or share any personal information, browsing history, or full URLs. The extension has no analytics, no telemetry, and no account.

## What data PhishGuard touches

| Data | Where it goes | Why |
|---|---|---|
| URLs of pages you visit | **Stays on your device.** Domain matching is performed locally against blocklist data. The full URL is never transmitted. | To classify whether you're on a known scam / phishing site |
| The **first letter** of a domain you visit | Sent to `raw.githubusercontent.com` as part of a request to fetch the corresponding blocklist shard (e.g. `shard-a.json` for any domain starting with "a"). GitHub sees only the shard filename, which reveals only the first letter — not the full URL, host, or referrer | To download the relevant slice of the 2.5M-domain blocklist |
| Your extension settings (language, warning style, custom whitelist/blocklist, Safe Browsing API key) | `chrome.storage.local` — stays on your device | To remember your preferences |
| Blocklist shards | `Cache API` (`phishguard-shards-v1`) — stays on your device, refreshed every hour | Performance — avoids re-downloading shards |

## What PhishGuard does **not** do

- ❌ No telemetry, analytics, error reporting, or "anonymous usage stats" — none
- ❌ No account, sign-in, or registration
- ❌ No advertising IDs, tracking pixels, or third-party trackers
- ❌ Full URLs, page contents, search queries, form data, cookies, and history are **never** transmitted off-device
- ❌ No data is sold or shared with anyone

## Third-party services

PhishGuard contacts the following hosts only:

1. **`raw.githubusercontent.com`** — to fetch blocklist shards from the public open-source [phishguard-niki/blocklist-data](https://github.com/phishguard-niki/blocklist-data) repository. GitHub may log the request's IP address per their own privacy policy. Only the shard filename (= first letter of a domain) is included in the URL path.

2. **`safebrowsing.googleapis.com`** — **only if** you provide your own Google Safe Browsing API key in the extension settings. Without an API key, this service is never contacted. When enabled, the URL being checked is sent to Google per [Safe Browsing's privacy terms](https://policies.google.com/privacy). This feature is opt-in.

3. **`165.npa.gov.tw` and other 38 threat-intelligence feeds** — these are scraped by a **server-side** GitHub Actions job in our public blocklist-data repo, not by your browser. Your browser only ever downloads the pre-aggregated shard files from GitHub.

## Permissions PhishGuard requests, and why

| Permission | Why it's required |
|---|---|
| `host_permissions: <all_urls>` | Required to check every page you navigate to. Without it, PhishGuard cannot detect scam sites in real time. The extension only **reads** the URL — it does not modify page content, intercept form data, or send any URL anywhere |
| `webNavigation` | To know when you navigate to a new page so we can check the URL |
| `scripting` | To inject the warning overlay/interstitial on dangerous pages |
| `storage` | To save your settings on your device (no remote storage) |

## Open source

The full source code is published under the MIT license at <https://github.com/phishguard-niki/Phishguard>. You can audit exactly what the extension does. The blocklist itself is also open at <https://github.com/phishguard-niki/blocklist-data>.

## Contact

- Bug reports & questions: <https://github.com/phishguard-niki/Phishguard/issues>
- Maintainer: phishguard-niki

## Changes to this policy

If this policy changes materially, the new version will be published in this file in the repository, with the effective date updated. The extension version that the change applies to will be noted at the top.
