import json
import os
import sys
from datetime import datetime, timezone

SARIF_PATH = "results/nuclei-findings.sarif"
BASELINE_PATH = "config/security-baseline.json"
# Use GITHUB_STEP_SUMMARY in CI, or fall back to a local Markdown file in Git Bash
SUMMARY_PATH = os.environ.get("GITHUB_STEP_SUMMARY", "results/step-summary.md")

def clean_cell(val):
    """Sanitizes text so pipes and newlines do not break Markdown table columns."""
    if not val:
        return "-"
    return str(val).replace("|", "\\|").replace("\n", " ").strip()

suppressions = []
if os.path.exists(BASELINE_PATH):
    with open(BASELINE_PATH, "r", encoding="utf-8") as bf:
        suppressions = json.load(bf).get("suppressions", [])

now = datetime.now(timezone.utc).replace(tzinfo=None)

def check_suppression(rule_id, uri_str):
    for entry in suppressions:
        if entry.get("rule_id") == rule_id:
            target = entry.get("target_path", "")
            if target and target not in uri_str:
                continue
            exp_str = entry.get("expires_at", "-")
            if exp_str and exp_str != "-":
                try:
                    exp_date = datetime.strptime(exp_str, "%Y-%m-%d")
                    if now > exp_date:
                        return False, f"Expired on {exp_str}", exp_str
                except ValueError:
                    pass
            return True, entry.get("reason", "Accepted risk"), exp_str
    return False, "Unsuppressed active finding", "-"

if not os.path.exists(SARIF_PATH):
    print(f"[*] SARIF file not found at {SARIF_PATH}. Exiting cleanly.")
    sys.exit(0)

with open(SARIF_PATH, "r", encoding="utf-8") as sf:
    sarif_data = json.load(sf)

rows = []
unhandled_count = 0
suppressed_count = 0

for run in sarif_data.get("runs", []):
    for result in run.get("results", []):
        level = result.get("level", "").lower()
        rule_id = result.get("ruleId", "unknown")
        message = result.get("message", {}).get("text", "")

        locations = result.get("locations", [])
        uri_str = "-"
        if locations:
            uri_str = (
                locations[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "-")
            )

        if level == "error":
            is_sup, note, expires = check_suppression(rule_id, uri_str)
            if is_sup:
                suppressed_count += 1
                status_badge = "🟡 Suppressed"
                details = note
            else:
                unhandled_count += 1
                status_badge = "🔴 Actionable"
                details = f"{message} ({note})"

            rows.append({
                "status": status_badge,
                "rule_id": clean_cell(rule_id),
                "uri": clean_cell(uri_str),
                "details": clean_cell(details),
                "expires": clean_cell(expires)
            })

# Build the Markdown Job Summary
gate_passed = unhandled_count == 0
header_status = "✅ Passed" if gate_passed else "❌ Failed (Build Blocked)"

md_lines = [
    "## 🛡️ Nuclei Security Audit Summary",
    "",
    f"**Gate Status:** {header_status}  ",
    f"**Actionable High/Critical:** `{unhandled_count}` | **Suppressed (Baseline):** `{suppressed_count}`",
    "",
]

if rows:
    md_lines.extend([
        "| Status | Rule ID | Target Endpoint | Details / Justification | Expires |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ])
    for r in rows:
        md_lines.append(
            f"| {r['status']} | `{r['rule_id']}` | `{r['uri']}` | {r['details']} | `{r['expires']}` |"
        )
else:
    md_lines.append("> 🎉 Zero High or Critical findings were detected during this scan.")

md_lines.append("")
markdown_output = "\n".join(md_lines)

# Write to GITHUB_STEP_SUMMARY (or local results/step-summary.md)
os.makedirs(os.path.dirname(SUMMARY_PATH) if os.path.dirname(SUMMARY_PATH) else ".", exist_ok=True)
with open(SUMMARY_PATH, "a", encoding="utf-8") as sum_file:
    sum_file.write(markdown_output + "\n")

# Print to terminal for Git Bash visibility
print("\n" + markdown_output)
print(f"[+] Markdown summary written to: {SUMMARY_PATH}")

sys.exit(0 if gate_passed else 1)
