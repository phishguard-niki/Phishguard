#!/bin/bash
# Phishguard OpenClaw Skill - Setup Script
# Downloads blocklist data from GitHub and verifies installation

set -e

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SKILL_DIR/data/blocklist-shards"
GITHUB_REPO="https://raw.githubusercontent.com/phishguard-niki/Phishguard/master"
SHARDS_INDEX_URL="$GITHUB_REPO/data/blocklist-shards/index.json"

echo "🛡️  Phishguard OpenClaw Skill Setup"
echo "===================================="

# Check dependencies
echo ""
echo "Checking dependencies..."

if ! command -v python3 &>/dev/null; then
    echo "❌ Python3 is required. Install: brew install python3"
    exit 1
fi
echo "✅ Python3 found"

if ! command -v curl &>/dev/null; then
    echo "❌ curl is required."
    exit 1
fi
echo "✅ curl found"

# Download or update blocklist data
echo ""
download_shards() {
    echo "📥 Downloading blocklist shards from GitHub..."
    mkdir -p "$DATA_DIR"

    # Download index first
    curl -fsSL "$SHARDS_INDEX_URL" -o "$DATA_DIR/index.json"

    # Parse index and download each shard
    SHARD_FILES=$(python3 -c "
import json
with open('$DATA_DIR/index.json') as f:
    idx = json.load(f)
for v in set(idx.values()):
    print(v)
")

    TOTAL=0
    DOWNLOADED=0
    for shard in $SHARD_FILES; do
        TOTAL=$((TOTAL + 1))
    done

    for shard in $SHARD_FILES; do
        DOWNLOADED=$((DOWNLOADED + 1))
        echo "  [$DOWNLOADED/$TOTAL] Downloading $shard..."
        curl -fsSL "$GITHUB_REPO/data/blocklist-shards/$shard" -o "$DATA_DIR/$shard"
    done

    echo "✅ Downloaded $TOTAL shard files"
}

if [ -d "$DATA_DIR" ] && [ "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
    DOMAIN_COUNT=$(python3 -c "
import json, glob
total = 0
for f in glob.glob('$DATA_DIR/shard-*.json'):
    try:
        d = json.load(open(f))
        total += len(d.get('domains', []))
    except: pass
print(total)
")
    echo "✅ Blocklist data found: $DOMAIN_COUNT domains"
    echo ""
    read -p "🔄 Update to latest blocklist? (y/N) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        download_shards
    fi
else
    download_shards
fi

# Count domains
DOMAIN_COUNT=$(python3 -c "
import json, glob
total = 0
for f in glob.glob('$DATA_DIR/shard-*.json'):
    try:
        d = json.load(open(f))
        total += len(d.get('domains', []))
    except: pass
print(total)
")
echo ""
echo "📊 Total domains in blocklist: $DOMAIN_COUNT"

# Test
echo ""
echo "Running quick test..."
RESULT=$(python3 "$SKILL_DIR/lib/check_url.py" "fm888.org" 2>&1)
if echo "$RESULT" | grep -q "critical"; then
    echo "✅ Test passed: fm888.org correctly detected as scam"
else
    echo "❌ Test failed. Result: $RESULT"
    exit 1
fi

RESULT=$(python3 "$SKILL_DIR/lib/check_url.py" "google.com" 2>&1)
if echo "$RESULT" | grep -q '"risk_level": "low"'; then
    echo "✅ Test passed: google.com correctly identified as safe"
else
    echo "❌ Test failed. Result: $RESULT"
    exit 1
fi

echo ""
echo "===================================="
echo "✅ Phishguard setup complete!"
echo "   Blocklist: $DOMAIN_COUNT domains"
echo ""
echo "To update blocklist later, run:"
echo "  bash $SKILL_DIR/setup.sh"
echo ""
