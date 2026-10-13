"""CI helper: verify `snitchy selftest` output contains the curl request.

Checks the three things Snitchy must get right on a real Mac:
  1. the app       (curl, found on disk at /usr/bin/curl)
  2. the hostname  (example.com, from DNS or the HTTPS hello)
  3. the signature (Apple, since curl ships with macOS)
"""

import json
import sys

rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
print("%d connections captured" % len(rows))
curl = [r for r in rows if r.get("app") == "curl"]
if not curl:
    sys.exit("FAIL: no connection attributed to curl")
hits = [r for r in curl if (r.get("domain") or "").endswith("example.com")]
if not hits:
    sys.exit("FAIL: curl connections found, but none named example.com: %r" % curl)
row = hits[0]
print("curl -> example.com:", json.dumps(row, indent=2))
problems = []
if row.get("path") != "/usr/bin/curl":
    problems.append("path is %r, expected /usr/bin/curl" % row.get("path"))
if row.get("signing") != "apple":
    problems.append("signing is %r, expected apple" % row.get("signing"))
if row.get("direction") != "out":
    problems.append("direction is %r, expected out" % row.get("direction"))
if not row.get("bytes_in"):
    problems.append("no received bytes counted")
if problems:
    sys.exit("FAIL: " + "; ".join(problems))
print("PASS")
