"""
One-off cleaner for example_apps.csv -> produces a canonical, always-parseable CSV.

Fixes:
  - merged rows where a newline was dropped (a row parsing to >2 fields)
  - doubled '/app-ads.txt/app-ads.txt...' suffixes -> single '/app-ads.txt'
  - leading/trailing whitespace on bundle id and URL
  - fully empty / bundle-less rows (dropped)
  - exact duplicate (bundle, url) rows (dropped)
Quoted fields containing commas (valid CSV) are preserved.
"""
import csv
import re
import shutil

SRC = 'example_apps.csv'
BACKUP = 'example_apps.raw.csv'
OUT = 'example_apps.csv'  # overwrite in place after backup

DOUBLED = re.compile(r'(/app-ads\.txt)(?:/app-ads\.txt)+', re.IGNORECASE)


def normalize_url(url):
    url = (url or '').strip()
    # Collapse repeated /app-ads.txt/app-ads.txt -> /app-ads.txt
    url = DOUBLED.sub(r'\1', url)
    return url


def repair_overlong(fields):
    """A row parsed to >2 fields => one or more dropped newlines glued records
    together. The glue point is always right after a URL ending in 'app-ads.txt'
    immediately followed by the next bundle id. Re-split on that boundary."""
    joined = ','.join(fields)
    records = []
    # Split into "bundle,<...>app-ads.txt" chunks; the boundary is the .txt that
    # is immediately followed by a non-comma char (the next bundle id).
    pattern = re.compile(r'app-ads\.txt(?=[^,/])', re.IGNORECASE)
    last = 0
    for m in pattern.finditer(joined):
        chunk = joined[last:m.end()]
        records.append(chunk)
        last = m.end()
    tail = joined[last:]
    if tail.strip(','):
        records.append(tail)
    # Each chunk should now be "bundle,url"
    out = []
    for chunk in records:
        parts = chunk.split(',', 1)
        if len(parts) == 2:
            out.append((parts[0], parts[1]))
        elif len(parts) == 1 and parts[0].strip():
            out.append((parts[0], ''))
    return out


def main():
    shutil.copy2(SRC, BACKUP)
    print(f"Backed up original -> {BACKUP}")

    rows_in = 0
    cleaned = []          # list of (bundle, url)
    n_repaired_lines = 0
    n_records_from_repair = 0
    n_suffix_fixed = 0
    n_empty_dropped = 0

    with open(SRC, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        for fields in reader:
            if not fields:
                continue
            rows_in += 1
            if len(fields) > 2:
                n_repaired_lines += 1
                recs = repair_overlong(fields)
                n_records_from_repair += len(recs)
            elif len(fields) == 2:
                recs = [(fields[0], fields[1])]
            else:  # 1 field
                recs = [(fields[0], '')]

            for bundle, url in recs:
                bundle = (bundle or '').strip()
                if not bundle or bundle.lower() in ('nan', 'none'):
                    n_empty_dropped += 1
                    continue
                new_url = normalize_url(url)
                if new_url != (url or '').strip():
                    n_suffix_fixed += 1
                cleaned.append((bundle, new_url))

    # Drop exact duplicate (bundle, url) pairs, preserving first-seen order
    seen = set()
    deduped = []
    n_dup_dropped = 0
    for rec in cleaned:
        if rec in seen:
            n_dup_dropped += 1
            continue
        seen.add(rec)
        deduped.append(rec)

    with open(OUT, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(deduped)

    print("\n=== Cleaning report ===")
    print(f"  data rows read:            {rows_in}")
    print(f"  merged lines repaired:     {n_repaired_lines} -> {n_records_from_repair} records")
    print(f"  doubled-suffix URLs fixed: {n_suffix_fixed}")
    print(f"  empty/bundle-less dropped: {n_empty_dropped}")
    print(f"  exact duplicate rows:      {n_dup_dropped}")
    print(f"  rows written (clean):      {len(deduped)}")


if __name__ == '__main__':
    main()
