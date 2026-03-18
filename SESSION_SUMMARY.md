# Anti-Scam Guard Extension (v0.4.2)

## Project Location
- Extension root: `/work/` (manifest.json, background.js, content/, ui/)
- Auto-updater: `/work/anti-scam-extension-v042-auto/`
- Output data: `/work/data/blocklist.json` + `/work/data/blocklist-shards/`
- Smoke test: `/work/test_background.js` (48 cases, run after every change)

## What Was Done (2026-03-18)

### Source Expansion (11 → 34 sources)
- Config: `anti-scam-extension-v042-auto/config/sources.json`
- Added: PhishTank, CERT.PL, Phishing Army, BlocklistProject, Jarelllama Scam, ScamSniffer, NoCoin, Feodo Tracker, durablenapkin, Disconnect, AA419, JPCERT
- Dropped (dead): PeterDaveHello (404), PhishStats CSV (deprecated), DShield (format→gzip), CryptoScamDB (502)
- Result: **1,637,504 unique domains** (was 460,574)
- Keywords: 20 (was 9), added crypto + TW scam terms

### Files Created
| File | Purpose |
|------|---------|
| `config/sources.json` | 34 source entries |
| `config/keywords.txt` | 20 keyword terms |
| `config/local-seeds.txt` | Empty placeholder |
| `test_sources.js` | HTTP availability test per source |
| `run_update.sh` | Full pipeline: fetch_global → auto_update → verify → shard check |

### background.js Bug Fixes (v0.4.2 session fixes, 8 fixes total)

| # | Bug | Fix |
|---|-----|-----|
| 1 | `login` in path blocks legitimate sites (homeplus.net.tw) | Moved to `riskyIfSuspiciousDomain` — only triggers on suspicious TLDs |
| 2 | `verify`/`secure`/`support` same false positive problem | Same treatment as #1 |
| 3 | `limited` blocks HK/UK company names | Same treatment |
| 4 | `baseDomain('bank.com.tw')` → `com.tw` (wrong) | Added ccTLD table (18 countries: TW/HK/CN/UK/AU/JP/KR/SG/MY/PH/TH/VN/ID/BR/IN/ZA/NZ/MX) |
| 5 | 47MB blocklist.json loaded entirely into memory | Lazy shard loading — loads only needed shard by first letter |
| 6 | **Blocklist never worked** — `Array.isArray(obj)` on `{phishing_domains:[...]}` → always false → empty Set | Fixed by shard loader reading `obj.domains` |
| 7 | Google search `?q=投資` triggers RISKY_PATH | Search engines' query strings now skipped |
| 8 | Chinese URL paths encoded (`%E6%8A%95%E8%B3%87`) don't match keywords | Added `decodeURIComponent()` before matching |

### auto_update_v2.js Fixes
- **Whitelist**: 50+ major domains (google.com, facebook.com, paypal.com, etc.) excluded from blocklist — phishing feeds sometimes include them as targets (被仿冒對象) not attackers
- **Subdomain whitelist**: `accounts.google.com`, `docs.google.com` etc. also filtered (checks parent domain)

### Current Heuristic Logic (background.js)
```
Always block:     airdrop, seed-phrase, claim-reward
Suspicious TLD:   login, verify, secure, support, limited, refund, bonus, wallet, gift,
                  客服, 驗證, 投資, 私訊, 限時, 贈品, 錢包, 返利, 出金, 入金, 博弈, 合約, 交易所
Search engines:   Query string (?q=) completely skipped for google/bing/yahoo/ddg/baidu/naver
Suspicious TLDs:  .xyz, .top, .icu, .buzz, .click, .club, .loan, .work,
                  .gq, .ml, .tk, .cf, .ga, pages.dev, workers.dev, duckdns.org,
                  000webhostapp.com, weebly.com, blogspot.com
```

### Known Remaining Issues
- `TW_165_fake_investment`: TIMEOUT from container (works from user's TW network)
- `CN_POLICE_fake_sites`: 403 geo-blocked (works from CN IP)
- `TW_165_article_api`: Returns 0 hosts — NPA may have changed API format
- `run_update.sh`: CN_POLICE 403 causes unhandled promise rejection in auto_update_v2.js retry chain (non-fatal, `|| true` in shell script)

### How to Run
```bash
cd /work/anti-scam-extension-v042-auto
node test_sources.js          # Test source availability
bash run_update.sh            # Full pipeline → ../data/blocklist.json
cd /work
node test_background.js       # 48-case smoke test for background.js
```

### Next Steps (TODO)
- Fix `TW_165_article_api` — investigate NPA API format change
- Consider adding more APAC sources (HKCERT, SingCERT, ThaiCERT)
- Consider adding user whitelist UI in extension options page
- The unhandled promise rejection in auto_update_v2.js retry chain should be properly fixed (race condition in setTimeout+resolve chain for 403 retries)
