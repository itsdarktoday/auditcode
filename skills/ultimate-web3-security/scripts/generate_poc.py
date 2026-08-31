#!/usr/bin/env python3
"""
Exploit PoC Generator for ultimate-web3-security.
Converts an attack hypothesis into a structured, executable Foundry test.
"""

import os
import sys
import argparse
from pathlib import Path

POC_TEST_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

contract Exploit_{finding_slug} is Test {{
    address public attacker = makeAddr("attacker");
    address public victim = makeAddr("victim");

    function setUp() public {{
        {fork_setup}
        // Deploy mocks or attach to target addresses
    }}

    function test_exploit_{finding_slug}() public {{
        // [1. Baseline Pre-State]
        // Record victim and attacker balances

        // [2. Attacker State Priming / Exploitation]
        vm.startPrank(attacker);
        // Step 1: Execute exploit transactions
        vm.stopPrank();

        // [3. Assert Invariant Violation & Harm]
        // assertGt(attackerProfit, 0);
        // assertLt(victimBalanceAfter, victimBalanceBefore);
    }}
}}
"""

def main():
    parser = argparse.ArgumentParser(description='Generate executable Foundry PoC scaffold.')
    parser.add_argument('slug', help='Unique finding slug/identifier (e.g. share-inflation-vault)')
    parser.add_argument('--output-dir', default='ultimate-audit/poc', help='Output directory for PoC')
    parser.add_argument('--fork-url', default='', help='Optional RPC URL for mainnet fork')
    parser.add_argument('--block-number', default='0', help='Optional block number for pinned fork')
    args = parser.parse_args()

    out_dir = Path(args.output_dir) / args.slug
    out_dir.mkdir(parents=True, exist_ok=True)

    fork_setup = ""
    if args.fork_url:
        fork_setup = f'vm.createSelectFork("{args.fork_url}", {args.block_number});'
    else:
        fork_setup = '// Standalone unit test setup'

    poc_code = POC_TEST_TEMPLATE.format(
        finding_slug=args.slug.replace('-', '_'),
        fork_setup=fork_setup
    )

    test_file = out_dir / 'Exploit.t.sol'
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(poc_code)

    readme_file = out_dir / 'README.md'
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(f'# Exploit PoC: {args.slug}\n\n')
        f.write('## Execution Command\n\n```bash\n')
        if args.fork_url:
            clean_slug = args.slug.replace('-', '_')
            f.write(f'forge test --match-test test_exploit_{clean_slug} -vvvv --fork-url {args.fork_url} --fork-block-number {args.block_number}\n')
        else:
            clean_slug = args.slug.replace('-', '_')
            f.write(f'forge test --match-test test_exploit_{clean_slug} -vvvv\n')
        f.write('```\n')

    print(f'Successfully scaffolded PoC at {test_file}')
    print(f'README with execution command generated at {readme_file}')

if __name__ == '__main__':
    main()
