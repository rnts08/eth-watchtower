# ETH Watchtower — Development Plan

## Completed (v0.4.0 — v0.6.0)

- Behavioral heuristics: RugPull detection via LP token burns, EarlyBuy detection via mint-to-pair near deployment, DustDistribution detection for small-value multi-recipient mints.
- Per-contract risk overrides: `Enabled`, `ScoreMultiplier`, `EventOverrides`, `MaxRiskScore` on `Config.Contracts`; `applyRiskOverrides` and `isEventEnabled` at all 8 emission sites.
- Persistence layer: deployer history and code cache persisted via bbolt (`db_path` config, default `eth-watch.db`), loaded on startup and written on each mutation.

---

## Short-Term — High Value, Quick Wins

### 1. Notification Integrations (Alerting)
Findings are written to a JSONL file with no external notification mechanism. Add configurable alert channels:
- **Discord webhook** — POST finding payload per configured severity threshold
- **Telegram bot** — message via Bot API with optional inline keyboard
- **Slack webhook** — standard message format

Config structure:
```json
{
  "alerts": {
    "discord_webhook": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "slack_webhook": "",
    "min_risk_score": 100
  }
}
```

### 2. Test Coverage for Untested Handlers
- `handleLiquidityEvent` / `handleTradeEvent` — crafted DEX PairCreated/Swap logs
- `handleFlashLoan` standalone (not just flash-mint via buffer)
- `handleRugPull` — mock tracked pair + deployer burn scenario
- `cacheCode` eviction — verify oldest entry removed at `maxCacheSize` capacity
- `detectTokenType` with nil/empty input

### 3. Refactor: Deduplicate Default Definitions
`loadConfig` and `reloadConfig` both define the same `defaultEventScores` map and heuristic fallbacks. Extract to a shared `setHeuristicDefaults(cfg *Config)` function.

### 4. Refactor: Split `handleTransfer`
At ~850 lines, this single function handles mint detection, whale detection, dust distribution, early buy detection, and rug pull dispatch. Extract each heuristic into its own method for testability and maintainability.

---

## Medium-Term — Feature Expansions

### 5. L2 Chain Support
Config already tracks Arbitrum/Optimism/Polygon/Base bridge addresses. Add:
- Detect L2-specific events (sequencer updates, state commitments)
- Track canonical bridge deposits/withdrawals as risk signals
- Per-chain risk profiles (separate `EventScores` per network)

### 6. HTTP API Server
Serve a lightweight REST API alongside the existing `/metrics` endpoint using only `net/http`:
- `GET /findings?since=N&min_score=N` — query findings
- `GET /contracts/:address` — current tracked state
- `GET /health` — RPC status, subscription health, DB status

### 7. Rate Limiting per RPC
Replace the simple semaphore with a token-bucket rate limiter per RPC endpoint to avoid being rate-limited by providers while maximizing throughput.

### 8. Live WebSocket Dashboard
Push findings and metrics in real-time to a browser-based HUD via WebSocket. Complements the static `index.html` landing page (served via GitHub Pages for project promotion).

---

## Long-Term — Advanced

### 9. ML Scoring Integration
Pass findings to an external scoring model for enrichment:
- Configurable webhook URL for real-time inference
- Blend ML score into `RiskScore` (e.g., `final = max(heuristic, ml)`)
- Feature vector extraction from raw logs for model training

### 10. Multi-Watcher Coordination
- Shared state across instances via BoltDB or external store
- Partitioned RPC assignment — each watcher owns a subset of contracts
- Leader election for single-writer patterns

### 11. On-Chain Alert Subscriptions
- Deploy a lightweight alert contract that emits standardized events
- Watcher subscribes to its own alert contract, bridging on-chain signals to off-chain notification channels
