import csv
import re
from pathlib import Path

root = Path(__file__).resolve().parents[2]
spec = root / "api/openapi/common.yaml"
out = root / "docs/ps5-port/rest-path-index.csv"
rows = []
for number, line in enumerate(spec.read_text(encoding="utf-8").splitlines(), 1):
    match = re.match(r"^  (/api/[^:]+): \{ \$ref: '\./([^'#]+)#", line)
    if match:
        rows.append((match.group(1), match.group(2), number, "not assessed"))
if not rows:
    raise SystemExit("No paths found; check upstream YAML layout before using this index")
with out.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(["path", "domain_spec", "common_yaml_line", "status"])
    writer.writerows(rows)
print(f"Wrote {len(rows)} indexed paths to {out}")
