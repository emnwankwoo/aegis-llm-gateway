"""Pretty-print AegisGate JSON responses for scripts/demo.sh (no jq needed).

Usage:  curl ... | python3 scripts/summarize.py chat <http_code>
        curl ... | python3 scripts/summarize.py stats
"""

import json
import sys


def chat(code: str, raw: str) -> None:
    try:
        d = json.loads(raw)
    except ValueError:
        print(f"  HTTP {code} (non-JSON body)")
        return
    if "action" not in d:
        print(f"  HTTP {code}: {d.get('detail')}")
        return
    print(f"  HTTP {code}  action={d['action'].upper()}  risk={d['risk_score']:.2f}")
    for f in d.get("input_findings", []):
        print(f"    input  {f['rule_id']:<10} {f['description']}")
    for f in d.get("output_findings", []):
        print(f"    output {f['rule_id']:<10} {f['description']}")
    for k, v in (d.get("redactions") or {}).items():
        print(f"    masked {k} x{v}")
    text = d.get("response") or d.get("message")
    if text:
        print("  > " + text[:400].replace("\n", "\n  > "))


def stats(raw: str) -> None:
    s = json.loads(raw)
    print("  events:", s["total_events"], " by action:", s["by_action"])
    print("  top rules:", ", ".join(f"{r} x{n}" for r, n in s["top_rules"]))


if __name__ == "__main__":
    data = sys.stdin.read()
    if sys.argv[1] == "chat":
        chat(sys.argv[2], data)
    else:
        stats(data)
