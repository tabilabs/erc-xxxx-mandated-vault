# ERC-XXXX: Mandated Execution for Tokenized Vaults

[![CI](https://github.com/tabilabs/erc-xxxx-mandated-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/tabilabs/erc-xxxx-mandated-vault/actions/workflows/ci.yml)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.28-blue.svg)](https://soliditylang.org/)

Reference implementation for **ERC-XXXX: Risk-Constrained Mandated Execution for ERC-4626 Vaults**.

This ERC defines a minimal, interoperable interface for delegated strategy execution on ERC-4626 tokenized vaults — allowing external executors (e.g., AI agents or solvers) to submit on-chain executions without custody of private keys, while the vault enforces hard risk constraints on-chain.

## Overview

```
Authority --signs (EIP-712)--> Mandate (constraints + adapter allowlist)
    |
    v
Executor --submits--> vault.execute(mandate, actions, signature, proofs, extensions)
    |
    v
Vault: validate -> snapshot preAssets -> CALL adapters -> snapshot postAssets -> circuit breaker
```

### Core Mechanism

- **EIP-712 Mandate**: Authority signs constraints off-chain (drawdown bounds, adapter allowlist, executor restriction)
- **Adapter Allowlist**: Merkle root commitment over `(address, extcodehash)` pairs — pins runtime bytecode
- **Circuit Breaker**: Post-execution enforcement via `totalAssets()` pre/post comparison
  - Single-execution drawdown: `maxDrawdownBps`
  - Cumulative epoch drawdown: `maxCumulativeDrawdownBps` (high-water mark)
- **Extension Mechanism**: Hash-committed extensions for strategy-specific constraints (e.g., `SelectorAllowlist@v1`)

## Quick Start

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Install

```bash
git clone https://github.com/tabilabs/erc-xxxx-mandated-vault.git
cd erc-xxxx-mandated-vault
forge install
```

### Build

```bash
forge build
```

### Test

```bash
forge test -vvv
```

### Format

```bash
forge fmt
```

## Project Structure

```
src/
├── interfaces/
│   └── IERCXXXXMandatedVault.sol   # Core interface (ERC-165 compatible)
├── MandatedVault.sol                # Reference implementation (OZ v5.x)
├── adapters/
│   ├── UniswapV3SwapAdapter.sol     # Example: Uniswap V3 swap adapter
│   └── AaveSupplyAdapter.sol        # Example: Aave V3 supply/withdraw adapter
└── mocks/
    └── MockAdapter.sol              # Test mocks and helpers
test/
└── MandatedVault.t.sol              # Comprehensive test suite (73 tests)
script/
└── Deploy.s.sol                     # Deployment script
```

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Adapter pinning | `extcodehash` in Merkle leaf | Pins runtime bytecode; upgradeable proxies explicitly unsafe |
| Cumulative tracking | Epoch-based high-water mark | Prevents "death by a thousand cuts" incremental drain |
| Authority transfer | Two-step (propose + accept) | Prevents accidental lockout |
| Native ETH | Forbidden in Core (`value == 0`) | Most `totalAssets()` implementations only track ERC-20 |
| Adapter calls | `CALL` only (no `DELEGATECALL`) | Prevents storage-context takeover |
| Extension hash | `keccak256(extensions)` committed in mandate | Prevents executor-side extension tampering |

## Specification

Full specification: [ERC-XXXX Draft](https://github.com/tabilabs/tabi-eipxxx/blob/main/docs/draft.md)

## Security Considerations

> **This reference implementation is unaudited. Do not use in production without a thorough security review.**

Key security assumptions:

1. **`totalAssets()` must be manipulation-resistant** within the same transaction. Vaults using spot AMM prices are vulnerable to flash-loan attacks that bypass the circuit breaker.
2. **Upgradeable proxy adapters** can change behavior without changing proxy bytecode — do not allowlist them without implementation-pinning.
3. **Epoch management** requires periodic `resetEpoch()` by the authority to prevent stale cumulative drawdown tracking.

See the full [Security Considerations](https://github.com/tabilabs/tabi-eipxxx/blob/main/docs/draft.md#security-considerations) section in the specification.

## Dependencies

- [OpenZeppelin Contracts v5.x](https://github.com/OpenZeppelin/openzeppelin-contracts) — ERC4626, EIP712, MerkleProof, ReentrancyGuard
- [Forge Std](https://github.com/foundry-rs/forge-std) — Testing framework

## License

This project is licensed under [CC0-1.0](LICENSE).
