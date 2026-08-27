---
name: 06_reporting
description: Audit Report Generation Phase Checklist
tags: ["reporting"]
---

# Audit Report Synthesis Checklist

1. **Consolidate State**:
   - Ensure all findings have clear impact descriptions, root causes, PoC test snippets, and unified diff fixes (`+`/`-`).
   - Verify all in-scope contracts and SLOC counts are accurate.
   - Review the Access Control Matrix and Invariant Table.

2. **Generate Institutional-Grade Report**:
   - Run `report_gen(format: "markdown", output_path: "audit-report.md")`.
   - Export structured JSON summary via `report_gen(format: "json", output_path: "audit-summary.json")`.
   - Review executive summary metrics and severity distribution tables.
