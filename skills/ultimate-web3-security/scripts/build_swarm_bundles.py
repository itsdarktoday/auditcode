#!/usr/bin/env python3
"""
Swarm Bundle Builder for ultimate-web3-security.
Packs target repository source files into source.md and constructs
specialized bundles for all 18 swarm agents.
"""

import os
import sys
import glob
import argparse
from pathlib import Path

AGENT_SPECIALTIES = {
    "agent-1-math-precision": "Focus on fixed-point arithmetic (mulDiv, Ray/Wad), zero-share mints, rounding direction asymmetry, compounding dust drift, and catastrophic cancellation.",
    "agent-2-reentrancy-transient": "Focus on Checks-Effects-Interactions violations, read-only view reentrancy (Balancer/Curve), ERC-777/1155 recipient hooks, and EIP-1153 TSTORE/TLOAD dirty states.",
    "agent-3-access-control": "Focus on missing modifiers, uninitialized proxy logic, ownership transition gaps, tx.origin, and capability store leaks.",
    "agent-4-economic-mev": "Focus on flash loan price distortion, sandwichable TWAP windows, atomic arbitrage, and liquidity manipulation.",
    "agent-5-oracle-pricing": "Focus on stale Chainlink latestRoundData, missing heartbeat validation, L2 sequencer downtime grace periods, and decimal conversion shifts.",
    "agent-6-lending-cdp": "Focus on health factor math, collateral seizing bonuses, soft-liquidation cascades, bad debt socialization, and unliquidatable positions.",
    "agent-7-amm-hooks": "Focus on Uniswap v4 hook return delta spoofing, beforeSwap/afterSwap reentrancy, tick boundary drift, and stableswap invariants.",
    "agent-8-vault-inflation": "Focus on ERC-4626 first-depositor share inflation, direct balance donation attacks, and unharvested yield sandwiching.",
    "agent-9-governance-voting": "Focus on flash-loan voting power, snapshot block manipulation, proposal cancellation races, and timelock bypasses.",
    "agent-10-signatures-permits": "Focus on EIP-712 cross-chain replay, signature malleability (s, v), and permit front-running DoS.",
    "agent-11-upgradeability-proxies": "Focus on storage layout collisions across upgrades, uninitialized implementation contracts, and missing storage gaps.",
    "agent-12-dos-griefing": "Focus on unbounded dynamic array iteration, push-over-pull payment reverts, and 63/64th gas exhaustion.",
    "agent-13-crosschain-bridges": "Focus on cross-chain message replay, destination gas trapping, and lock/mint parity drift.",
    "agent-14-assembly-lowlevel": "Focus on free memory pointer (0x40) corruption, dirty upper bits in assembly casting, and returndatacopy buffer overflows.",
    "agent-15-gap-hunter-numerical": "Focus on seams between math rounding and economic incentives across multi-contract interactions.",
    "agent-16-gap-hunter-trust": "Focus on seams between trust boundaries, external callbacks, and intermediate state mutations.",
    "agent-17-gap-hunter-flow": "Focus on seams between asynchronous settlement queues, state machines, and multi-contract transaction graphs.",
    "agent-18-skeptic-adversary": "Focus strictly on DISPROVING findings by identifying hidden guards, Solidity 0.8+ overflow reverts, and committed invariant defenses."
}

SHARED_RULES = """
# Universal Audit Rules & Output Schema

1. You are an elite attacker. Your objective is finding concrete vulnerabilities with executable proof.
2. Suspicious code is NOT a finding unless you prove reachability and an unbroken path to material harm (WHO loses WHAT).
3. Privilege Boundary: Admin actions matching documented spec are NOT findings unless an unprivileged amplifier is present.
4. Output Format:
   For every candidate finding:
   - File & Function (with line numbers)
   - Target Invariant Broken (INV-x)
   - Root Cause (1-2 sentences)
   - Attack Path (Step-by-step transaction trace)
   - Proof / Concrete Numbers
   - Impact (Quantified loss)
   - Minimal Fix (Actionable code diff)
5. If you cannot prove the complete path, emit as a LEAD with the unverified step explicitly stated.
"""

def collect_source_files(target_dir, extensions=['.sol', '.rs', '.move', '.circom']):
    """Recursively collects all in-scope source files, excluding tests and mocks."""
    target_path = Path(target_dir).resolve()
    source_files = []
    
    exclude_dirs = {'test', 'tests', 'mocks', 'mock', 'lib', 'node_modules', 'out', 'artifacts', 'build', '.git'}
    exclude_files = {'*.t.sol', '*Test*.sol', '*Mock*.sol'}

    for ext in extensions:
        for file_path in target_path.rglob(f'*{ext}'):
            # Check exclusions
            parts = set(file_path.parts)
            if parts.intersection(exclude_dirs):
                continue
            if any(file_path.match(pat) for pat in exclude_files):
                continue
            source_files.append(file_path)
            
    return sorted(source_files)

def build_source_md(source_files, output_path):
    """Compiles all source files into a single structured source.md."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('# In-Scope Source Code Repository\n\n')
        for file_path in source_files:
            f.write(f'### File: {file_path}\n\n')
            ext = file_path.suffix.lstrip('.')
            f.write(f'```{ext}\n')
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as sf:
                    f.write(sf.read())
            except Exception as e:
                f.write(f'// Error reading file: {e}\n')
            f.write('\n```\n\n')

def build_agent_bundles(source_md_path, bundle_dir):
    """Generates individual agent bundle markdown files."""
    os.makedirs(bundle_dir, exist_ok=True)
    with open(source_md_path, 'r', encoding='utf-8') as f:
        source_content = f.read()

    for agent_id, specialty in AGENT_SPECIALTIES.items():
        bundle_file = Path(bundle_dir) / f'{agent_id}-bundle.md'
        with open(bundle_file, 'w', encoding='utf-8') as f:
            f.write(f'# Audit Agent Bundle: {agent_id}\n\n')
            f.write(f'## Specialty Directive\n{specialty}\n\n')
            f.write(f'{SHARED_RULES}\n\n')
            f.write('---\n\n')
            f.write(source_content)
        print(f'Generated: {bundle_file} ({bundle_file.stat().st_size} bytes)')

def main():
    parser = argparse.ArgumentParser(description='Build audit agent bundles.')
    parser.add_argument('target', help='Path to target project repository')
    parser.add_argument('--output-dir', default='ultimate-audit/bundles', help='Directory for generated bundles')
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    bundle_dir = Path(args.output_dir).resolve()
    os.makedirs(bundle_dir, exist_ok=True)

    print(f'Scanning target: {target_dir}')
    source_files = collect_source_files(target_dir)
    print(f'Found {len(source_files)} in-scope source files.')

    source_md = bundle_dir / 'source.md'
    build_source_md(source_files, source_md)
    print(f'Compiled source.md at {source_md}')

    build_agent_bundles(source_md, bundle_dir)
    print(f'Successfully built all 18 agent bundles in {bundle_dir}')

if __name__ == '__main__':
    main()
