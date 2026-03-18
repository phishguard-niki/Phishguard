
# run_update.ps1 - call auto_update_v2 with common options
param(
  [string]$RepoRoot = "$PSScriptRoot/.."
)
$auto = Join-Path $RepoRoot 'anti-scam-extension-v042-auto'
node (Join-Path $auto 'auto_update_v2.js') `
  --sources (Join-Path $auto 'config/sources.json') `
  --out (Join-Path $RepoRoot 'anti-scam-extension-v042/data/blocklist.json') `
  --keywords (Join-Path $auto 'config/keywords.txt') `
  --urlhaus_only_online `
  --phishstats_min_score 6 `
  --shards_dir (Join-Path $RepoRoot 'anti-scam-extension-v042/data/blocklist-shards') `
  --shards 27
