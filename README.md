# AuditCode

<p align="center">
  <pre align="center">
             █   █                 █     
█▀▀█ █  █ █▀▀█ █ ▀█▀▀ █▀▀▀ █▀▀█ █▀▀█ █▀▀▀
█▄▄█ █  █ █  █ █  █   █    █  █ █  █ █▀▀▀
▀  ▀ ▀▀▀▀ ▀▀▀▀ ▀  ▀▀  ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀▀▀▀
  </pre>
</p>

<p align="center">
  <strong>Autonomous Multi-Agent Web3 & Smart Contract Security Auditing Harness in Your Terminal.</strong><br>
  Specialist Swarm Architecture &bull; Shared Audit State &bull; Foundry & Static Tooling &bull; 20+ LLM Providers
</p>

<p align="center">
  <a href="https://github.com/itsdarktoday/auditcode/releases/latest"><img src="https://img.shields.io/github/v/release/itsdarktoday/auditcode?style=flat-square&color=red" alt="Release"></a>
  <a href="https://github.com/itsdarktoday/auditcode/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/itsdarktoday/auditcode"><img src="https://img.shields.io/github/stars/itsdarktoday/auditcode?style=flat-square" alt="Stars"></a>
</p>

---

**AuditCode** is an autonomous smart contract security auditing harness built for your terminal. Point it at a Solidity, Vyper, Foundry, or Solana/Anchor codebase and it parses ASTs, inspects storage layouts, dispatches a swarm of 14 specialized auditing agents, runs automated static tools (Slither, Cyfrin Aderyn), writes executable Foundry PoC exploits, and generates institutional-grade audit reports — exactly how a top-tier human auditor team operates.

Hard-forked from [OpenCode](https://github.com/anomalyco/opencode) and [PentestCode](https://github.com/s0ld13rr/pentestcode), stripped of web2 pentesting abstractions and re-engineered from the ground up for Web3 security and smart contract auditing. Created and maintained by **[itsdarktoday](https://github.com/itsdarktoday)** and **[0xscarfac3](https://github.com/0xscarfac3)**.

> **v1.0 Ready** — Battle-tested on EVM protocols, DeFi vaults, and competitive audit contests (Code4rena, Sherlock, Cantina, Immunefi). [File an issue](https://github.com/itsdarktoday/auditcode/issues) to report feedback or contribute.

---

## ⚡ What it does

One command in, an institutional-grade smart contract audit out:

```
you: "audit the smart contracts in this repo, focus on vault inflation and oracle manipulation"
```

| Stage | What the agent swarm does |
|:---|:---|
| **1. Scope Recon** | `contract_inspect` parses AST, extracts public/external functions, SLOC, compiler versions, inheritance trees, and proxy architectures into durable state. |
| **2. Static Analysis** | `slither_parse` & `aderyn_parse` run AST detectors and automated linters, auto-triaging findings into severity buckets. |
| **3. Threat Modeling** | `invariant_agent` drafts formal accounting invariants (`totalAssets >= totalSupply`), while `access_control` maps the Protocol Access Control Matrix. |
| **4. Deep Multi-Agent Audit** | 10 specialized subagents review in parallel: `math_precision` checks rounding/scaling, `economic_security` analyzes flashloans/oracles, `reentrancy` checks cross-contract flows, `periphery_agent` validates ERC standard compliance. |
| **5. 4-Gate Quality Filter** | `critic` runs all candidate findings through 4 strict verification gates (Reachability, Control Flow, Financial Impact, Minimal Fix) to purge false positives. |
| **6. PoC Verification** | `poc_dev` writes runnable Foundry test suites (`foundry_test`) with `-vvvv` execution traces to mathematically prove exploitability. |
| **7. Final Synthesis** | `reporter` generates comprehensive Markdown & JSON audit reports with executive summaries, CVSS scores, root causes, and diff remediation. |

---

## 📦 Install

### Via npm:
```bash
npm install -g auditcode-ai
```

### Via curl installer:
```bash
curl -fsSL https://raw.githubusercontent.com/itsdarktoday/auditcode/main/install.sh | bash
```

A single self-contained binary — no Bun, Node.js, or runtime installation required. Supports Linux (x64, arm64) and macOS (Apple Silicon, Intel).

<details>
<summary><strong>Alternative Installation Options</strong></summary>

#### Pin Specific Version:
```bash
AUDITCODE_VERSION=1.0.0 curl -fsSL https://raw.githubusercontent.com/itsdarktoday/auditcode/main/install.sh | bash
```

#### Custom Install Directory:
```bash
AUDITCODE_INSTALL=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/itsdarktoday/auditcode/main/install.sh | bash
```

#### Build From Source:
```bash
git clone https://github.com/itsdarktoday/auditcode.git
cd auditcode
bun install
bun run --cwd packages/opencode build
# Binary output at dist/auditcode-<os>-<arch>/bin/auditcode
```

</details>

---

## 🚀 Quick Start

```bash
auditcode auth login          # Connect your AI provider (Anthropic, OpenAI, DeepSeek, etc.)
auditcode                     # Launch interactive full-screen TUI audit dashboard
auditcode /path/to/contracts  # Open a specific smart contract workspace
auditcode run "Audit Vault.sol for rounding errors and first-depositor attacks" # Headless one-shot
```

Works with 20+ LLM providers via [ai-sdk](https://github.com/vercel/ai) — Anthropic Claude 3.7 / 3.5 Sonnet, OpenAI GPT-4o / o3, DeepSeek-V3 / R1, Google Gemini 2.0 Pro, AWS Bedrock, Ollama, and local models.

---

## 🧠 How It Works: The Swarm Architecture

AuditCode replaces single-prompt LLM hallucinations with a **specialized multi-agent swarm** and a **persistent shared audit memory**.

```
                              ┌───────────────────────────┐
                              │      User / Auditor       │
                              └─────────────┬─────────────┘
                                            │
                              ┌─────────────▼─────────────┐
                              │    audit (Lead Auditor)   │
                              └─────────────┬─────────────┘
                                            │
     ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
     │                  │                   │                   │                  │
┌────▼────┐        ┌────▼────┐         ┌────▼────┐         ┌────▼────┐        ┌────▼────┐
│  recon  │        │ static  │         │invariant│         │ 10 Deep │        │ critic  │
│  agent  │        │ analyst │         │  agent  │         │Auditors │        │ & poc   │
└─────────┘        └─────────┘         └─────────┘         └────┬────┘        └─────────┘
                                                                │
             ┌──────────────────┬───────────────────┬───────────┴───────┬──────────────────┐
             │                  │                   │                   │                  │
      ┌──────▼──────┐    ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐    ┌──────▼──────┐
      │math_precis'n│    │access_contrl│     │economic_defi│     │ reentrancy  │    │solana_analys│
      └─────────────┘    └─────────────┘     └─────────────┘     └─────────────┘    └─────────────┘
```

### The 14 Specialized Web3 Agents:

1. **`audit`** *(Lead Coordinator)* — Orchestrates the 6-phase audit lifecycle, dispatches specialist agents, manages quality gates, and synthesizes findings.
2. **`recon`** *(Architecture & Scope)* — Maps protocol contracts, inheritance trees, proxy patterns, entry points, and SLOC metrics.
3. **`static_analyst`** *(Automated Tooling)* — Runs and triages Slither and Cyfrin Aderyn AST detectors into normalized findings.
4. **`math_precision`** *(Arithmetic & Precision)* — Division-before-multiplication, rounding direction inversion, 1e18 scaling, vault share inflation.
5. **`access_control`** *(Auth & Governance)* — Uninitialized proxies (`_disableInitializers`), missing access modifiers, signature replay/malleability, timelocks.
6. **`economic_security`** *(DeFi & Oracles)* — Flash loan exploits, AMM spot-price manipulation, MEV sandwiching, Chainlink stale price feeds & sequencer uptime.
7. **`reentrancy`** *(Execution Flow)* — Read-only reentrancy on view functions, cross-contract/cross-function reentrancy, ERC777/1155 hooks, transient storage.
8. **`invariant_agent`** *(Properties & Fuzzing)* — Formulates protocol accounting invariants (`totalAssets >= totalSupply`) and fuzzing properties for Echidna/Foundry.
9. **`periphery_agent`** *(Token Standards)* — Non-standard ERC20 quirks (USDT missing return, fee-on-transfer, rebasing), ERC4626 standard deviations.
10. **`boundary_agent`** *(Edge Cases)* — Zero-value transfers, `type(uint256).max` limits, off-by-one errors, first-depositor griefing, pause state deadlock.
11. **`poc_dev`** *(Exploit Developer)* — Writes and executes executable Foundry test files (`test_Exploit()`) to prove vulnerabilities with `-vvvv` traces.
12. **`solana_analyst`** *(Solana & Anchor)* — Missing signer checks, PDA bump seed collisions, duplicate mutable accounts, account re-initialization.
13. **`critic`** *(Quality Gatekeeper)* — Applies the 4-Gate Filter (Reachability, Control Flow, Financial Impact, Fix Validation) to eliminate false positives.
14. **`reporter`** *(Report Synthesizer)* — Compiles professional Markdown and JSON audit deliverables.

---

## 💾 Shared Audit State

Every agent writes to and reads from a persistent, structured **Audit State** (`~/.auditcode/engagements/<name>/`):

- **In-Scope Contracts** — Name, path, compiler version, proxy pattern, SLOC, functions, modifiers, custom errors.
- **Protocol Invariants** — Accounting invariants, solvency rules, and formal property definitions.
- **Actor Access Control Matrix** — Roles, privileged functions, timelock delays, multisig thresholds.
- **Vulnerabilities** — Categorized by severity (🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ⚪ Gas, ℹ️ Info), status (`suspected`, `confirmed`, `poc_verified`, `false_positive`), CVSS, root cause, and unified diff fixes.
- **PoC Test Suite** — Executable Foundry test files, command triggers, and verified gas/execution traces.

State survives sessions: pause, resume, or export reports anytime without losing context.

---

## 🛠️ Specialized Web3 Tools

| Tool | Purpose |
|:---|:---|
| [`contract_inspect`](file:///packages/opencode/src/tool/contract-inspect.ts) | AST parsing, SLOC counting, public/external function extraction, proxy detection |
| [`slither_parse`](file:///packages/opencode/src/tool/slither-parse.ts) | Runs Slither and automatically converts JSON detector findings into typed audit state |
| [`aderyn_parse`](file:///packages/opencode/src/tool/aderyn-parse.ts) | Runs Cyfrin Aderyn AST static analysis and populates vulnerability ledger |
| [`foundry_test`](file:///packages/opencode/src/tool/foundry-test.ts) | Executes `forge test` with `-vvvv` traces, gas profiling, and auto-verifies PoCs |
| [`storage_layout`](file:///packages/opencode/src/tool/storage-layout.ts) | Inspects EVM storage slot packing and flags missing `__gap` storage collisions |
| [`signature_lookup`](file:///packages/opencode/src/tool/signature-lookup.ts) | Resolves 4-byte selectors (`0xa9059cbb`) and event topics via OpenChain database |
| [`erc_validate`](file:///packages/opencode/src/tool/erc-validate.ts) | Validates ERC20, ERC721, ERC1155, and ERC4626 compliance and inflation hazards |
| [`phase_control`](file:///packages/opencode/src/tool/phase-control.ts) | Manages 6 audit phases with strict quality transition gates |
| [`report_gen`](file:///packages/opencode/src/tool/report-gen.ts) | Exports institutional Markdown and JSON audit reports |
| [`state_query`](file:///packages/opencode/src/tool/state-query.ts) | Reads contracts, invariants, actor roles, PoCs, and findings |
| [`state_update`](file:///packages/opencode/src/tool/state-update.ts) | Records mutations and critic verdicts in atomic transactions |

---

## 📚 Curated Web3 Security Skills (`skills/`)

AuditCode includes 19 curated knowledge packs loaded dynamically on demand:

- **6 Phase Checklists**: `01_scope_recon`, `02_static_analysis`, `03_threat_modeling`, `04_deep_audit`, `05_poc_verification`, `06_reporting`.
- **8 Vulnerability Deep Dives**: `reentrancy`, `oracle_manipulation`, `erc4626_vaults`, `math_precision`, `access_control`, `signatures`, `upgradeability`, `solana_security`.
- **5 Protocol Playbooks**: `defi_lending`, `amm_dex`, `erc4626_vault_audit`, `bridge_crosschain`, `solana_anchor_audit`.

---

## 🎯 Slash Commands & Modes

Control your live audit session with interactive slash commands:

| Command | Description |
|:---|:---|
| `/status` | Live audit dashboard — in-scope contracts, SLOC, findings severity breakdown, active phase |
| `/contracts` | Table of all in-scope smart contracts, proxy patterns, and compiler settings |
| `/vulns` | Vulnerabilities categorized by severity with PoC verification status |
| `/invariants` | Protocol accounting and state machine invariants |
| `/actors` | Protocol Access Control Matrix (roles, privileged functions, timelocks) |
| `/poc` | Registered Foundry PoC test cases and execution traces |
| `/slither [path]` | Run Slither static analysis and ingest findings into state |
| `/aderyn` | Run Cyfrin Aderyn AST scanner and ingest findings into state |
| `/forge [test]` | Execute Foundry PoC test suite with trace capture |
| `/phase [next\|name]` | Phase manager with automated quality gates |
| `/report [path]` | Export final institutional audit report |

---

## ⚙️ Configuration

Config lives at `.auditcode/auditcode.jsonc`:

```jsonc
{
  "$schema": "https://auditcode.ai/schema.json",
  "provider": {
    "anthropic": {
      "model": "claude-3-7-sonnet-latest"
    }
  },
  "agent": {
    "audit": {
      "temperature": 0.1
    }
  }
}
```

---

## 🤝 Contributing

Contributions, bug reports, and new Web3 skills are welcome! If you encounter an issue or want to contribute a new vulnerability detector:

1. Open an issue on GitHub: [https://github.com/itsdarktoday/auditcode/issues](https://github.com/itsdarktoday/auditcode/issues)
2. Submit PRs following conventional commits (`feat:`, `fix:`, `refactor:`, `test:`)
3. Test locally using `bun typecheck` and `bun test`

---

## 📄 License

MIT License &copy; 2026 **[itsdarktoday](https://github.com/itsdarktoday)** & **[0xscarfac3](https://github.com/0xscarfac3)**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Crafted with &hearts; for the Web3 security community by <a href="https://github.com/itsdarktoday">itsdarktoday</a> &amp; <a href="https://github.com/0xscarfac3">0xscarfac3</a> &bull; Hard fork of OpenCode
</p>
