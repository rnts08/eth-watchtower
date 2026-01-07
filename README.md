# ETH Watchtower

![Go CI](https://github.com/rnts08/eth-watcher/actions/workflows/ci.yml/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/rnts08/eth-watcher)](https://goreportcard.com/report/github.com/rnts08/eth-watcher)

[https://rnts08.github.io/eth-watchtower/]

ETH Watchtower is a real-time Ethereum event monitoring tool written in Go. It connects to an Ethereum RPC node via WebSocket to detect and analyze various on-chain activities, including contract deployments, token mints, liquidity creation, and DEX trades.

## Features

- **Contract Discovery**: Detects new smart contract deployments and identifies token standards (ERC20, ERC721, ERC1155).
- **Mint Detection**: Monitors `Transfer` events to detect token minting activities (transfers from the zero address).
- **DEX Monitoring**: Watches for liquidity pool creation and token swaps on configured DEXes (e.g., Uniswap V2).
- **Whale Watch**: Flags ERC20 transfers that exceed a configured value threshold.
- **Large Approval**: Flags ERC20 approvals that exceed a configured value threshold or are infinite.
- **Static Analysis**: Scans bytecode for risk factors like `SelfDestruct`, `HiddenMint`, `WriteToSlotZero`, `ReturnBomb`, `ERC777Reentrancy`, `DelegateCallToZero`, `CostlyLoop`, `ProxyDestruction`, `MetamorphicExploit`, `HardcodedSelfDestruct`, `UnsafeDelegateCall`, and `UncheckedMath`.
- **Metrics**: Exposes Prometheus metrics for monitoring the watcher's health and detected events.
- **Resilience**: Includes a watchdog to detect stalled RPC connections, failover support for multiple RPC endpoints, and a circuit breaker to temporarily avoid failing nodes.
- **Graceful Shutdown**: Handles OS signals (`SIGINT`, `SIGTERM`) for clean termination.

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

## Building

To build the application executable:

```bash
go build -o eth-watch
```

## Running

Start the watcher by providing the path to your configuration file:

```bash
./eth-watch -config config.json
```

### Command Line Flags

- `-config`: Path to the configuration JSON file (default: `config.json`).
- `-metrics`: Address to serve Prometheus metrics (default: `:2112`).

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


### Tips and appreciations

***ETH/ERC20:*** 0x968cC7D93c388614f620Ef812C5fdfe64029B92d

***SOL:*** HB2o6q6vsW5796U5y7NxNqA7vYZW1vuQjpAHDo7FAMG8

***BTC:*** bc1qkmzc6d49fl0edyeynezwlrfqv486nmk6p5pmta

## Full version includes more analyics

#### Vulnerability Detection

- **ReadOnlyReentrancy**: Detects external calls followed by state reads (read-only reentrancy risk).
- **ArbitraryStorageWrite**: Detects storage writes where the slot is derived from calldata.
- **UninitializedPointer**: Detects writes to storage slot 0 via uninitialized pointers.
- **UncheckedEcrecover**: Detects `ecrecover` return value not checked against zero.
- **MissingZeroCheck**: Detects missing zero-address validation in transfers.
- **SignatureReplay**: Detects signature usage without nonces.
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
- **UncheckedLowLevelCall**: Detects low-level calls where the boolean return value is ignored.
- **ReentrancyNoGasLimit**: Detects calls that forward all gas, increasing reentrancy risk.
- **UnprotectedEtherWithdrawal**: Detects withdrawal functions that do not check state (e.g. ownership or balance).
- **UncheckedTransfer**: Detects ERC20 transfer calls where the return value is ignored.

#### Honeypot & Scam Patterns

- **FakeToken**: Detects contracts mimicking ERC20 signatures but lacking storage logic.
- **Minting**: Detects minting capabilities.
- **StrawManContract**: Detects "cash out" patterns that are actually traps (e.g., hidden reverts, delegatecalls).
- **MaliciousProxy**: Detects usage of known malicious implementation addresses.
- **GasGriefingLoop**: Detects loops designed to consume gas.
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

#### Proxy & Metamorphic

- **NonStandardProxy**: Detects proxies that do not follow EIP-1967.
- **ProxySelectorClash**: Detects proxies with potential selector clashes between proxy and implementation.
- **SuspiciousDelegate**: Detects delegatecalls to hardcoded addresses.
- **DelegateCallToSelf**: Detects `delegatecall` to `address(this)`, a pattern often used in metamorphic contracts.

#### Control Flow & Loops

- **DoSGasLimit**: Detects loops bounded by dynamic data (DoS vector).
- **DeadCode**: Detects unreachable code.

#### Context & Environment

- **TimestampDependence**: Detects logic conditional on `block.timestamp`.
- **BadRandomness**: Detects usage of `blockhash` for randomness.
- **WeakRandomness**: Detects usage of `difficulty` or `prevrandao`.
- **BlockStuffing**: Detects usage of `gaslimit`.
- **AntiContractCheck**: Detects checks on `extcodesize` (often used to block smart contract interactions).
- **CodeHashCheck**: Detects checks on `extcodehash`.
- **TxOrigin**: Detects usage of `tx.origin` for authorization.
- **BlockTimestampManipulation**: Detects usage of `block.timestamp` in comparison operations.

#### Access Control

- **PrivilegedSelfDestruct**: Detects self-destructs protected by access control.
- **UnprotectedSelfDestruct**: Detects self-destructs reachable without authorization checks.
