---
name: 02_static_analysis
description: Automated Static Analysis & Scanning Phase Checklist
tags: ["static_analysis", "enumeration"]
---

# Static Analysis & Tool Scanning Checklist

1. **Slither Static Analysis**:
   - Run `slither_parse(target_path: ".")` or execute `slither . --json slither.json`.
   - Focus on high-impact detectors: `reentrancy-eth`, `arbitrary-send-erc20`, `unprotected-upgrade`, `uninitialized-state`.
   - Triage informational warnings and record leads into state.

2. **Cyfrin Aderyn AST Scanning**:
   - Run `aderyn_parse(run_aderyn: true)` or parse `aderyn-report.json`.
   - Ingest high/medium detectors directly into audit state.

3. **Custom Heuristics & Grep Passes**:
   - Grep for `delegatecall`, `selfdestruct`, `tx.origin`, `assembly`, `unchecked`.
   - Grep for spot-price calls: `getReserves()`, `slot0()`.
   - Grep for raw ERC20 transfers without SafeERC20: `.transfer(`, `.transferFrom(`.
