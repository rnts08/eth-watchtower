# ETH Watchtower — Development Plan

## Completed (v0.4.0 — v0.9.0)

- **v0.4.0**: Behavioral heuristics — RugPull, EarlyBuy, DustDistribution detection.
- **v0.5.0**: Per-contract risk overrides — `Enabled`, `ScoreMultiplier`, `EventOverrides`, `MaxRiskScore`.
- **v0.6.0**: Persistence layer via bbolt — `db_path` config, startup load, write-on-mutate.
- **v0.7.0**: Development plan TODO.md.
- **v0.8.0** (Refactoring + Tests):
  - 18 new tests: liquidity, trade, flashloan, rugpull, cache eviction, edge cases.
  - `setHeuristicDefaults()` extracted — deduplicated ~50 lines, fixed `reloadConfig` missing defaults.
  - `handleTransfer` split into 5 methods: `detectMintToDeployer`, `detectEarlyBuy`, `detectDustDistribution`, `detectMultipleMints`, `detectWhaleTransfer`.
- **v0.9.0** (Bug Fixes):
  - Fixed dust threshold bug: `detectDustDistribution` now reads `w.dustThreshold` from config instead of hardcoded 1000.
  - Fixed data races: `dustRecipientSoft` and `dexPairs`/`dexSwaps` reads now under `configLock.RLock()`.
  - DB errors now logged instead of silently discarded.
  - Removed unused `maxRPCFailures`/`rpcTripDuration` constants.

---

## Short-Term — High Value, Quick Wins

### 1. Lock Safety: `maxCacheSize` Under Wrong Lock
`w.maxCacheSize` is written under `w.configLock.Lock()` but read under `w.codeCacheMu.Lock()` (different mutex). Move both accesses to a single lock or add synchronization.

### 2. Test `handleLiquidityOrTrade` Routing
No test verifies that `handleLiquidityOrTrade` correctly dispatches to `handleLiquidityEvent` vs `handleTradeEvent` based on topic hash matching. Add a test with mocked `w.dexPairs`/`w.dexSwaps`.

### 3. Add Missing Config Fields to config.json
- `ownership_transfers` in events block
- `dust_threshold`, `dust_recipient_soft` in heuristics
- `enabled`, `score_multiplier`, `event_overrides`, `max_risk_score` per-contract
- `analyzer_pool_size` top-level

### 4. Clean Up Orphaned `monitor` Block
The `monitor` block in `config.json` has no corresponding Go struct field. Either implement it or remove it.

### 5. Minor Code Cleanup
- `logFile.Close()` error silently discarded at shutdown (lines 313/588)
- `loadConfiguration` file close error silently discarded (line 1558)
- `RiskWeight` field in Config.Contracts is dead (superseded by `ScoreMultiplier`; keep for backward compat but mark deprecated)

---

## Medium-Term — Feature Expansions

### 6. L2 Chain Support
Config already tracks Arbitrum/Optimism/Polygon/Base bridge addresses. Add:
- Detect L2-specific events (sequencer updates, state commitments)
- Track canonical bridge deposits/withdrawals as risk signals
- Per-chain risk profiles (separate EventScores per network)

### 7. HTTP API Server
Serve a lightweight REST API alongside the existing `/metrics` endpoint using only `net/http`:
- `GET /findings?since=N&min_score=N` — query findings
- `GET /contracts/:address` — current tracked state
- `GET /health` — RPC status, subscription health, DB status

### 8. Rate Limiting per RPC
Replace the simple semaphore with a token-bucket rate limiter per RPC endpoint.

### 9. Live WebSocket Dashboard
Push findings and metrics in real-time to a browser-based HUD via WebSocket.

---

## Long-Term — Advanced

### 10. ML Scoring Integration
Pass findings to an external scoring model for enrichment:
- Configurable webhook URL for real-time inference
- Blend ML score into RiskScore
- Feature vector extraction from raw logs

### 11. Multi-Watcher Coordination
- Shared state across instances via BoltDB or external store
- Partitioned RPC assignment
- Leader election for single-writer patterns

### 12. On-Chain Alert Subscriptions
- Deploy a lightweight alert contract that emits standardized events
- Watcher subscribes to its own alert contract
