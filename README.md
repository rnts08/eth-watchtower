# ETH Watchtower

![CI Status](https://github.com/rnts08/eth-watcher/actions/workflows/ci.yml/badge.svg) ![Docker Build](https://github.com/rnts08/eth-watcher/actions/workflows/docker.yml/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/rnts08/eth-watcher)](https://goreportcard.com/report/github.com/rnts08/eth-watcher)

[https://rnts08.github.io/eth-watchtower/]

ETH Watchtower is a real-time Ethereum event monitoring tool written in Go. It connects to an Ethereum RPC node via WebSocket to detect and analyze various on-chain activities, including contract deployments, token mints, liquidity creation, and DEX trades.

## What is Checked?

When running against an RPC, ETH Watchtower performs deep inspection in two distinct phases:

### 1. Real-Time Event Monitoring

As blocks arrive, the engine analyzes transaction logs to detect:

- **Contract Deployments**: Instantly captures new bytecode for analysis.
- **Token Mints**: Detects `Transfer` events from the zero address, flagging potential infinite mint exploits or hidden premints.
- **Whale Movements**: Alerts on value transfers exceeding configured thresholds.
- **Suspicious Approvals**: Identifies infinite approvals or approvals to known malicious entities.
- **DEX Activity**: Monitors liquidity events and swaps on Uniswap-compatible protocols.
- **Flash Loans**: Detects large capital movements via flash loan callbacks.
- **Ownership Changes**: Tracks ownership renouncements (often fake) or transfers.

### 2. Static Bytecode Analysis

Every new contract bytecode is disassembled and scanned against a library of heuristic patterns (detailed in the sections below) to identify vulnerabilities, honeypots, and malicious logic.

## Features

- **Contract Discovery**: Detects new smart contract deployments and identifies token standards (ERC20, ERC721, ERC1155).
- **Mint Detection**: Monitors `Transfer` events to detect token minting activities (transfers from the zero address).
- **DEX Monitoring**: Watches for liquidity pool creation and token swaps on configured DEXes (e.g., Uniswap V2).
- **Whale Watch**: Flags ERC20 transfers that exceed a configured value threshold.
- **Large Approval**: Flags ERC20 approvals that exceed a configured value threshold or are infinite.
- **Static Analysis**: Scans bytecode for risk factors like `SelfDestruct`, `HiddenMint`, `WriteToSlotZero`, `ReturnBomb`, `ERC777Reentrancy`, `DelegateCallToZero`, `CostlyLoop`, `ProxyDestruction`, `MetamorphicExploit`, `HardcodedSelfDestruct`, `UnsafeDelegateCall`, `UncheckedMath`, `UncheckedCall`, `UncheckedSend`, and `UncheckedLowLevelCall`.
- **Metrics**: Exposes Prometheus metrics for monitoring the watcher's health and detected events.
- **Resilience**: Includes a watchdog to detect stalled RPC connections, failover support for multiple RPC endpoints, and a circuit breaker to temporarily avoid failing nodes.
- **Graceful Shutdown**: Handles OS signals (`SIGINT`, `SIGTERM`) for clean termination.

## Continuous Integration (CI)

This repository uses GitHub Actions to ensure code quality and supply chain security:

- **Tests & Linting**: Every push and pull request triggers the Go test suite (`make test`), race condition detection, and `golangci-lint`.
- **Performance Benchmarks**: Performance regressions are monitored via `make performance`.
- **Release Builds**: Pushing a tag (e.g., `v1.0.0`) triggers a cross-platform build for Linux, Windows, and macOS (AMD64/ARM64).
- **Artifact Signing**: Release artifacts are hashed (`checksums.txt`) and signed with GPG (`checksums.txt.asc`) to ensure integrity.
- **Docker Publishing**: A Docker image is automatically built and pushed to the GitHub Container Registry (GHCR).
- **Verification Script**: The `verify_release.sh` script is tested in a separate workflow to ensure it correctly validates GPG signatures and checksums.

## Prerequisites

- Go 1.24 or later
- An Ethereum RPC WebSocket endpoint (e.g., Infura, Alchemy, or a public node).

## Configuration

The application is configured via a JSON file (default: `config.json`).

Key configuration sections:

- `rpc`: List of WebSocket URLs for Ethereum nodes (supports failover).
- `events`: Toggles for specific event types (`transfers`, `liquidity`, `trades`).
- `dexes`: List of DEX event topics to watch.
- `whale_threshold`: Minimum value (in Wei) to flag a transfer as a "WhaleTransfer".
- `contracts`: List of specific contracts to monitor with associated metadata.

## Installation & Usage

### Option 1: Download Binary

1. Go to the Releases page.
2. Download the archive for your OS/Arch.
3. (Optional) Verify the download using the provided script:

    ```bash
    ./verify_release.sh
    ```

### Option 2: Build from Source

Clone the repository and build the executable:

```bash
git clone https://github.com/rnts08/eth-watcher.git
cd eth-watcher/src
make build
```

## Running

Start the watcher by providing the path to your configuration file:

```bash
./eth-watchtower -config config.json
```

### Command Line Flags

- `-config`: Path to the configuration JSON file (default: `config.json`).
- `-metrics`: Address to serve Prometheus metrics (default: `:2112`).

## Docker

You can also run ETH Watchtower using Docker.

### Building the Image

```bash
docker build -t eth-watchtower .
```

### Running the Container

Mount your `config.json` into the container:

```bash
docker run -d \
  -v $(pwd)/config.json:/app/config.json \
  -p 2112:2112 \
  --name eth-watchtower \
  eth-watchtower
```

## Testing

The project includes unit tests for event handling logic, token type detection, and concurrency safety.

To run the tests:

```bash
go test -v .
```

To run tests with the Go race detector enabled (recommended to verify thread safety):

```bash
go test -race -v .
```

## Output

### Events

Detected events are written to the configured output file (e.g., `eth-watch-events.jsonl`) in JSON Lines format.

Example:

```json
{"contract":"0x...","deployer":"0x...","block":123456,"tokenType":"ERC20","mintDetected":true,"riskScore":55,"flags":["MintDetected"],"txHash":"0x..."}
```

### Metrics

Prometheus metrics are exposed at `http://localhost:2112/metrics` (or the configured address).

Key metrics include:

- `eth_watcher_contracts_discovered_total`: Total number of new contracts discovered.
- `eth_watcher_mints_detected_total`: Total number of mints detected.
- `eth_watcher_trades_detected_total`: Total number of trades detected.
- `eth_watcher_flashloans_detected_total`: Total number of flashloans detected.
- `eth_watcher_rpc_latency_seconds`: RPC connection latency.
- `eth_watcher_active_subscriptions`: Current number of active WebSocket subscriptions.
- `eth_watcher_code_analysis_flags_total`: Total number of times a specific code analysis flag has been detected.

### Visualization

A Grafana dashboard configuration is provided in `grafana_dashboard.json`. You can import this JSON file into your Grafana instance to visualize the metrics exported by ETH Watchtower.

### Tips and appreciations

***ETH/ERC20:*** 0x968cC7D93c388614f620Ef812C5fdfe64029B92d

***SOL:*** HB2o6q6vsW5796U5y7NxNqA7vYZW1vuQjpAHDo7FAMG8

***BTC:*** bc1qkmzc6d49fl0edyeynezwlrfqv486nmk6p5pmta

#### Vulnerability Detection

- **ReadOnlyReentrancy**: Detects external calls followed by state reads (read-only reentrancy risk).
- **ArbitraryStorageWrite**: Detects storage writes where the slot is derived from calldata.
- **UninitializedPointer**: Detects writes to storage slot 0 via uninitialized pointers.
- **UncheckedEcrecover**: Detects `ecrecover` return value not checked against zero.
- **MissingZeroCheck**: Detects missing zero-address validation in transfers.
- **SignatureReplay**: Detects signature usage without nonces.
- **WriteToSlotZero**: Detects writing to storage slot 0, often a proxy implementation bug or uninitialized pointer.
- **TokenDraining**: Detects calls where the token address is user-controlled.
- **ArbitraryJump**: Detects jumps to destinations derived from calldata.
- **FrontRunning**: Detects transaction order dependency patterns (e.g., hash solution verification).
- **SignatureMalleability**: Detects `ecrecover` usage without strict s-value checks (EIP-2).
- **UninitializedConstructor**: Detects owner-setting logic that can be re-called.
- **GasTokenMinting**: Detects patterns associated with minting gas tokens via `SELFDESTRUCT` refunds.
- **IntegerTruncation**: Detects masking of calldata inputs that could lead to truncation.
- **UninitializedLocalVariables**: Detects usage of memory variables before they are written to, a common bug with storage pointers in memory.
- **UninitializedState**: Detects storage reads from slots that haven't been written to, implying uninitialized state usage.
- **PublicBurn**: Detects unprotected `burn` functions that can be called by anyone.
- **UnprotectedUpgrade**: Detects unprotected proxy `upgradeTo` functions.
- **AssemblyErrorProne**: Detects patterns prone to errors in inline assembly, like misusing storage pointers for memory operations.
- **ReinitializableProxy**: Detects proxies with an `initialize` function that can be called multiple times.
- **UnusedEvent**: Detects declared events that are never emitted.
- **MisleadingFunctionName**: Detects functions with common names (e.g., `transfer`) but with non-standard selectors.
- **UnrestrictedDelegateCall**: Detects `delegatecall` where the target address is not validated.
- **StrictBalanceEquality**: Detects strict equality checks on `address(this).balance`.
- **DivideBeforeMultiply**: Detects division before multiplication causing precision loss.
- **UncheckedReturnData**: Detects low-level calls where return data is ignored.
- **HardcodedGasLimit**: Detects calls with hardcoded gas amounts.
- **LockedEther**: Detects contracts that can receive ETH but have no way to withdraw it.
- **ShadowingState**: Detects state reads that are immediately popped (useless reads).
- **UncheckedMath**: Detects arithmetic operations without overflow checks (pre-0.8.0).
- **ReentrancyNoGasLimit**: Detects calls that forward all gas, increasing reentrancy risk.
- **UnprotectedEtherWithdrawal**: Detects withdrawal functions that do not check state (e.g. ownership or balance).
- **UncheckedTransfer**: Detects ERC20 transfer calls where the return value is ignored.
- **UncheckedTransferFrom**: Detects ERC20 `transferFrom` calls where the return value is ignored.
- **UncheckedCall**: Detects low-level calls where the return value is ignored.
- **UncheckedSend**: Detects `send` calls (gas=2300) where the return value is ignored.
- **UncheckedLowLevelCall**: Detects `call` with custom gas where the return value is ignored.
- **UncheckedCreate**: Detects contract creation where the result address is ignored.
- **MissingReturn**: Detects contracts that appear to be tokens but lack a RETURN opcode.
- **UncheckedDelegateCall**: Detects `delegatecall` where the return value is ignored.
- **ReinitializableProxy**: Detects proxies with an `initialize` function that can be called multiple times.
- **SelfDestruct**: Detects usage of the `SELFDESTRUCT` opcode.
- **ReentrancyGuard**: Detects usage of reentrancy guards (e.g., OpenZeppelin).
- **ERC777Reentrancy**: Detects usage of the ERC1820 registry, often associated with ERC777 reentrancy vectors.

#### Honeypot & Scam Patterns

- **FakeToken**: Detects contracts mimicking ERC20 signatures but lacking storage logic.
- **StrawManContract**: Detects "cash out" patterns that are actually traps (e.g., hidden reverts, delegatecalls).
- **GasGriefingLoop**: Detects loops designed to consume gas.
- **HardcodedSelfDestruct**: Detects `SELFDESTRUCT` with a hardcoded beneficiary address.
- **HiddenFee**: Detects transfers where the amount is reduced by a constant value.
- **FakeHighBalance**: Detects `balanceOf` returning hardcoded large values.
- **FakeTransferEvent**: Detects `Transfer` events without storage updates.
- **PhantomFunction**: Detects do-nothing functions that trap funds.
- **OwnerTransferCheck**: Detects transfer functions restricted to the owner.
- **TradingCooldown**: Detects time-lock or cooldown mechanisms on transfers.
- **TaxToken**: Detects transfer logic involving division, indicative of transfer taxes.
- **PotentialHoneypot**: Detects transfer functions that write to state but don't emit Transfer events.
- **SuspiciousStateChange**: Detects state writes without prior reads (blind overwrites).
- **ZeroAddressTransfer**: Detects Transfer events to the zero address (burns) that are not from standard burn functions.
- **FakeReturn**: Detects a specific fake return pattern used to deceive callers.
- **NoTransferEvent**: Detects transfer functions that do not emit events.
- **HardcodedBlacklistedAddress**: Detects references to known malicious addresses (e.g., Tornado Cash router).
- **HiddenMint**: Detects minting logic hidden within transfer functions.
- **ReturnBomb**: Detects contracts that revert with large data or in a way to grief callers.
- **GasGriefing**: Detects usage of `INVALID` opcode or other gas-wasting patterns.

#### Proxy & Metamorphic

- **NonStandardProxy**: Detects proxies that do not follow EIP-1967.
- **MinimalProxy**: Detects EIP-1167 minimal proxy clones.
- **ProxySelectorClash**: Detects proxies with potential selector clashes between proxy and implementation.
- **SuspiciousDelegate**: Detects delegatecalls to hardcoded addresses.
- **DelegateCallToSelf**: Detects `delegatecall` to `address(this)`, a pattern often used in metamorphic contracts.
- **Metamorphic**: Detects usage of `CREATE2` (base detection).
- **ProxyDestruction**: Detects `delegatecall` combined with `selfdestruct` (proxy destruction risk).
- **MetamorphicExploit**: Detects `CREATE2` combined with `selfdestruct` (metamorphic exploit risk).
- **UnsafeDelegateCall**: Detects `delegatecall` using calldata, allowing arbitrary code execution.
- **DelegateCallToZero**: Detects `delegatecall` to the zero address.
- **DelegateCall**: Detects usage of `delegatecall` (base detection).

#### Control Flow & Loops

- **DoSGasLimit**: Detects loops bounded by dynamic data (DoS vector).
- **DeadCode**: Detects unreachable code.
- **InfiniteLoop**: Detects unconditional backward jumps.
- **CallInLoop**: Detects calls executed inside loops.
- **LoopDetected**: Detects any backward jump (base loop detection).
- **DelegateCallInLoop**: Detects delegatecalls executed inside loops.
- **FactoryInLoop**: Detects contract creation inside loops.
- **SelfDestructInLoop**: Detects self-destructs inside loops.
- **GasDependentLoop**: Detects loops with gas operations.
- **CostlyLoop**: Detects storage writes (`SSTORE`) inside loops.

#### Context & Environment

- **TimestampDependence**: Detects logic conditional on `block.timestamp`.
- **BadRandomness**: Detects usage of `blockhash` for randomness.
- **WeakRandomness**: Detects usage of `difficulty` or `prevrandao`.
- **BlockStuffing**: Detects usage of `gaslimit`.
- **AntiContractCheck**: Detects checks on `extcodesize` (often used to block smart contract interactions).
- **CodeHashCheck**: Detects checks on `extcodehash`.
- **TxOrigin**: Detects usage of `tx.origin` for authorization.
- **BlockTimestampManipulation**: Detects usage of `block.timestamp` in comparison operations.
- **GasPriceCheck**: Detects logic dependent on `tx.gasprice`.
- **CoinbaseCheck**: Detects logic dependent on `block.coinbase`.
- **BlockNumberCheck**: Detects logic dependent on `block.number`.
- **ChainIDCheck**: Detects logic dependent on `chainid`.
- **CheckOwnBalance**: Detects logic checking `address(this).balance`.
- **GasUsage**: Detects usage of the `GAS` opcode.

#### Access Control

- **PrivilegedSelfDestruct**: Detects self-destructs protected by access control.
- **UnprotectedSelfDestruct**: Detects self-destructs reachable without authorization checks.

#### Functionality & Standards

- **Mintable**: Detects minting function selectors.
- **Burnable**: Detects burning function selectors.
- **Ownable**: Detects ownership management selectors.
- **Blacklist**: Detects blacklist function selectors.
- **Upgradable**: Detects upgradeable proxy selectors.
- **InterfaceCheck**: Detects ERC165 interface checks.
- **FlashLoan**: Detects flash loan function selectors.
- **Withdrawal**: Detects withdrawal function selectors.
- **RenounceOwnership**: Detects ownership renouncement.

#### Code Structure & Quality

- **Stateless**: Detects contracts with no storage operations (often logic contracts or scams).
- **SuspiciousCodeSize**: Detects code size checks on itself.
- **IncorrectConstructor**: Detects potential constructor naming errors (Solidity <0.4.22).
- **LowLevelCall**: Detects usage of low-level `call`.
- **ContractFactory**: Detects contract creation (`create`).
- **CalldataSizeCheck**: Detects checks on `calldatasize`.

()<a href="https://buymeacoffee.com/timhbergsta">Buy me a beer</a>
