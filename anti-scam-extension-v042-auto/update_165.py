#!/usr/bin/env python3
"""
Fetch all Taiwan scam data sources and merge extracted domains
into the existing blocklist shards.
Sources: 165 NPA articles, 165 fraud websites CSV, MODA DNS suspension list
"""
import json, os, re, sys, time, urllib.request, ssl, csv
from io import StringIO

SHARD_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'blocklist-shards')
API_LIST = 'https://165.npa.gov.tw/api/article/list/9?page=1'
API_DETAIL = 'https://165.npa.gov.tw/api/article/detail/9/{id}'
FRAUD_WEBSITES_CSV = 'https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/033197D4-70F4-45EB-9FB8-6D83532B999A/resource/FEAA1683-4483-4FDC-B861-BC530789E2AB/download'
MODA_DNS_JSON = 'https://www-api.moda.gov.tw/OpenData/Files/16352'
HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AntiScamBot/1.0'}

def fetch(url, retries=3, verify_ssl=True):
    ctx = None
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            kwargs = {'timeout': 30}
            if ctx:
                kwargs['context'] = ctx
            return urllib.request.urlopen(req, **kwargs).read().decode('utf-8')
        except Exception as e:
            if i == retries - 1:
                raise
            time.sleep(1 * (i + 1))

def normalize_host(inp):
    v = str(inp or '').strip()
    if not v:
        return ''
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', v):
        v = 'http://' + v
    try:
        from urllib.parse import urlparse
        h = urlparse(v).hostname or ''
        h = h.lower()
        if h.startswith('www.'):
            h = h[4:]
        return h
    except:
        return str(inp or '').strip().lower().lstrip('www.')

def parse_165_table(html):
    """Extract domains from 165 article HTML: both <td> plain-text and <a href> URLs."""
    seen = set()
    out = []
    # Extract from <td> cells
    for m in re.finditer(r'<td[^>]*>([\s\S]*?)</td>', html, re.IGNORECASE):
        text = re.sub(r'<[^>]+>', '', m.group(1))
        text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&nbsp;', ' ').strip()
        if not text:
            continue
        for tok in re.split(r'[;\s]+', text):
            tok = tok.strip()
            if not tok or '.' not in tok:
                continue
            if re.match(r'^[\d.]+$', tok):
                continue
            if re.match(r'^[\u4e00-\u9fff\s]+$', tok):
                continue
            h = normalize_host(tok)
            if h and '.' in h and h not in seen:
                seen.add(h)
                out.append(h)
    # Also extract full URLs
    for m2 in re.finditer(r'\bhttps?://[^\s"<>]+', html, re.IGNORECASE):
        h = normalize_host(m2.group())
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out

# Government/edu domains to skip
SKIP_SUFFIXES = ('.gov.tw', '.edu.tw', '.npa.gov.tw')
# Whitelist of legitimate domains
WHITELIST = {
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'youtube.com',
    'google.com', 'google.com.tw', 'line.me', 'telegram.org', 'whatsapp.com',
    'apple.com', 'microsoft.com', 'amazon.com', 'yahoo.com',
    'shopee.tw', 'pchome.com.tw', 'momo.com',
}

def is_whitelisted(h):
    if h in WHITELIST:
        return True
    parts = h.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in WHITELIST:
            return True
    return False

def main():
    print('[1/4] Fetching 165 article list (source 1 of 3)...')
    txt = fetch(API_LIST)
    data = json.loads(txt)
    items = data if isinstance(data, list) else data.get('list', data.get('data', []))
    print(f'  Found {len(items)} articles')

    print('[2/4] Fetching article details and extracting domains...')
    all_hosts = set()
    errors = 0
    for i, item in enumerate(items):
        aid = item.get('id') or item.get('articleId') or item.get('ID')
        if not aid:
            continue
        try:
            detail_txt = fetch(API_DETAIL.format(id=aid))
            detail = json.loads(detail_txt)
            content = detail.get('content', '') or detail.get('data', {}).get('content', '')
            hosts = parse_165_table(str(content))
            # Filter
            for h in hosts:
                if any(h.endswith(s) for s in SKIP_SUFFIXES):
                    continue
                if is_whitelisted(h):
                    continue
                all_hosts.add(h)
        except Exception as e:
            errors += 1
        if (i + 1) % 50 == 0:
            print(f'  Processed {i+1}/{len(items)} articles ({len(all_hosts)} domains so far)')
        # Rate limiting
        time.sleep(0.1)

    print(f'  Total new domains from 165 articles: {len(all_hosts)} ({errors} fetch errors)')

    # --- Source 2: 165 Fraud Websites CSV ---
    print('[2b/4] Fetching 165 fraud websites CSV...')
    try:
        csv_text = fetch(FRAUD_WEBSITES_CSV, verify_ssl=False)
        # Remove BOM
        csv_text = csv_text.lstrip('\ufeff')
        reader = csv.DictReader(StringIO(csv_text))
        csv_count = 0
        for row in reader:
            url_val = row.get('WEBURL', '') or row.get('網址', '')
            if url_val:
                for tok in re.split(r'[;\s]+', url_val):
                    h = normalize_host(tok.strip())
                    if h and '.' in h and not any(h.endswith(s) for s in SKIP_SUFFIXES) and not is_whitelisted(h):
                        if h not in all_hosts:
                            csv_count += 1
                        all_hosts.add(h)
        print(f'  +{csv_count} new domains from fraud websites CSV')
    except Exception as e:
        print(f'  WARN: Failed to fetch fraud websites CSV: {e}')

    # --- Source 3: MODA DNS Suspension List ---
    print('[2c/4] Fetching MODA DNS suspension list...')
    try:
        moda_text = fetch(MODA_DNS_JSON)
        moda_data = json.loads(moda_text)
        moda_count = 0
        for item in moda_data:
            for key in ['網域名稱', '偽冒網址']:
                val = item.get(key, '')
                if val:
                    h = normalize_host(val)
                    if h and '.' in h and not any(h.endswith(s) for s in SKIP_SUFFIXES) and not is_whitelisted(h):
                        if h not in all_hosts:
                            moda_count += 1
                        all_hosts.add(h)
        print(f'  +{moda_count} new domains from MODA DNS suspension')
    except Exception as e:
        print(f'  WARN: Failed to fetch MODA data: {e}')

    print(f'  Total domains from all TW sources: {len(all_hosts)}')

    print('[3/4] Merging into existing shards...')
    shard_dir = os.path.abspath(SHARD_DIR)
    if not os.path.exists(shard_dir):
        print(f'  ERROR: Shard directory not found: {shard_dir}')
        sys.exit(1)

    index_path = os.path.join(shard_dir, 'index.json')
    with open(index_path) as f:
        index = json.load(f)

    total_added = 0
    for letter, filename in index.items():
        shard_path = os.path.join(shard_dir, filename)
        with open(shard_path) as f:
            shard = json.load(f)
        existing = set(shard.get('domains', []))
        # Find new hosts for this shard
        new_for_shard = set()
        for h in all_hosts:
            c = h[0].lower() if h else ''
            key = c if 'a' <= c <= 'z' else 'other'
            if key == letter and h not in existing:
                new_for_shard.add(h)
        if new_for_shard:
            merged = sorted(existing | new_for_shard)
            shard['domains'] = merged
            with open(shard_path, 'w') as f:
                json.dump(shard, f, separators=(',', ':'))
            total_added += len(new_for_shard)
            print(f'  {filename}: +{len(new_for_shard)} domains (total: {len(merged)})')

    print(f'\n[4/4] Done! Added {total_added} new domains from 165 articles.')

    # Verify specific domains
    for check in ['fm888.org', 'fuma888.net']:
        c = check[0]
        key = c if 'a' <= c <= 'z' else 'other'
        shard_path = os.path.join(shard_dir, index.get(key, ''))
        if os.path.exists(shard_path):
            with open(shard_path) as f:
                shard = json.load(f)
            found = check in shard.get('domains', [])
            print(f'  {check}: {"FOUND" if found else "NOT FOUND"} in {index.get(key)}')

if __name__ == '__main__':
    main()
