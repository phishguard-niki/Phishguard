#!/usr/bin/env bash
# run_update.sh — Full blocklist update pipeline
# Usage: bash run_update.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUT_DIR="../data"
OUT_FILE="$OUT_DIR/blocklist.json"
SHARDS_DIR="$OUT_DIR/blocklist-shards"

echo "=== Anti-Scam Blocklist Update Pipeline ==="
echo "Working dir: $SCRIPT_DIR"
echo ""

# Step 1: Fetch global regulatory feeds
echo "[1/4] Fetching global regulatory feeds (FCA, ASIC, SFC)..."
if node scripts/fetch_global_feeds.js; then
    echo "[OK] Global feeds fetched"
else
    echo "[WARN] Global feeds fetch had errors (continuing anyway)"
fi
echo ""

# Ensure local-seeds.txt exists (even if empty)
touch config/local-seeds.txt

# Ensure global feed files exist (empty fallback so auto_update doesn't crash)
mkdir -p config/global
for f in scamadviser-highrisk.txt crypto-exchange-scam.txt spamhaus-dbl.txt; do
    [ -f "config/global/$f" ] || echo "" > "config/global/$f"
done
for f in fca-scam.json asic-scam.json sfc-scam.json otx-scam.json; do
    [ -f "config/global/$f" ] || echo '{"domains":[]}' > "config/global/$f"
done

# Step 2: Run main updater
echo "[2/4] Running auto_update_v2.js (may take several minutes)..."
mkdir -p "$OUT_DIR" "$SHARDS_DIR"

# Some sources may 403/timeout (geo-blocked); auto_update catches per-source errors
# but unhandled promise rejections from retry chains can cause non-zero exit.
# We check for output file existence instead of relying on exit code.
node auto_update_v2.js \
    --sources config/sources.json \
    --out "$OUT_FILE" \
    --keywords config/keywords.txt \
    --urlhaus_only_online \
    --phishstats_min_score 5 \
    --shards_dir "$SHARDS_DIR" \
    --shards 27 || true

echo ""

# Step 3: Verify output
echo "[3/4] Verifying output..."

if [ ! -f "$OUT_FILE" ]; then
    echo "[FAIL] blocklist.json not found!"
    exit 1
fi

DOMAIN_COUNT=$(node -e "const j=JSON.parse(require('fs').readFileSync('$OUT_FILE','utf8')); console.log(j.phishing_domains.length)")
echo "  Domains in blocklist: $DOMAIN_COUNT"

KEYWORD_COUNT=$(node -e "const j=JSON.parse(require('fs').readFileSync('$OUT_FILE','utf8')); console.log(j.keywords.length)")
echo "  Keywords: $KEYWORD_COUNT"

VERSION=$(node -e "const j=JSON.parse(require('fs').readFileSync('$OUT_FILE','utf8')); console.log(j.version)")
echo "  Version: $VERSION"

# Step 4: Shard integrity check
echo ""
echo "[4/4] Shard integrity check..."

if [ -f "$SHARDS_DIR/index.json" ]; then
    SHARD_TOTAL=$(node -e "
const fs=require('fs');
const dir='$SHARDS_DIR';
const idx=JSON.parse(fs.readFileSync(dir+'/index.json','utf8'));
let total=0;
for(const [k,f] of Object.entries(idx)){
  const s=JSON.parse(fs.readFileSync(dir+'/'+f,'utf8'));
  total+=s.domains.length;
}
console.log(total);
")
    echo "  Shard total: $SHARD_TOTAL"
    if [ "$SHARD_TOTAL" = "$DOMAIN_COUNT" ]; then
        echo "  [PASS] Shard count matches blocklist total"
    else
        echo "  [FAIL] Shard mismatch: $SHARD_TOTAL vs $DOMAIN_COUNT"
    fi
else
    echo "  [WARN] index.json not found in shards dir"
fi

echo ""

# Step 5: Sync to openclaw-skill and push to GitHub
echo "[5/5] Syncing to openclaw-skill and pushing to GitHub..."

OPENCLAW_SHARDS="../openclaw-skill/data/blocklist-shards"
if [ -d "$OPENCLAW_SHARDS" ] && [ "$DOMAIN_COUNT" -gt 1000 ]; then
    cp -r "$SHARDS_DIR/"* "$OPENCLAW_SHARDS/"
    echo "  [OK] Synced shards to openclaw-skill"
fi

BLOCKLIST_REPO="/tmp/blocklist-data"
if [ -d "$BLOCKLIST_REPO/.git" ]; then
    cp -r "$SHARDS_DIR/"* "$BLOCKLIST_REPO/blocklist-shards/" 2>/dev/null
    cd "$BLOCKLIST_REPO"
    git add -A
    if git diff --cached --quiet; then
        echo "  [SKIP] No changes to push"
    else
        git commit -m "Auto-update blocklist $(date +%Y-%m-%d)" --no-gpg-sign
        git push origin main && echo "  [OK] Pushed to GitHub" || echo "  [WARN] Push failed (check auth)"
    fi
    cd "$SCRIPT_DIR"
else
    echo "  [SKIP] blocklist-data repo not found at $BLOCKLIST_REPO"
fi

echo ""
echo "=== Pipeline complete ==="
echo "Output: $OUT_FILE ($DOMAIN_COUNT domains)"
