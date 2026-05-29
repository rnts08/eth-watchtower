# ETH Watchtower Project - Next Steps

This document outlines the current status and remaining tasks for the ETH Watchtower project.

## Current Status Summary:

The project has seen significant progress across both backend and frontend components:

### Backend (`src/analyzer.go`, `src/main.go`, `config.json`)
*   **Heuristic Logic**:
    *   `ShadowingState` bug fixed.
    *   `BurstMint` and `SelfAllocation` heuristics implemented.
    *   `HighFrequencyDeployer` behavioral heuristic implemented in `main.go` (tracks deployment velocity).
 *   **Configurability**:
     *   All heuristic scores are now loaded dynamically from `config.json` into `analyzer.go`.
     *   RPC management parameters (`max_rpc_failures`, `rpc_trip_duration`, `max_code_cache_size`) are configurable via `config.json`.
     *   High-frequency deployer parameters (`high_frequency_threshold`, `high_frequency_score`, `high_frequency_window`) are configurable.
     *   Base score for new contracts (`new_contract_base_score`) and maximum risk score (`max_risk_score`) are configurable.
     *   All event handler scores (MintDetected, WhaleTransfer, ApprovalDetected, FlashLoanDetected, etc.) are now configurable via `event_scores` in `config.json`.
     *   Deployer history pruning now uses dedicated `high_frequency_window` config instead of reusing `rpc_trip_duration`.
     *   Removed dead `score` field from `selectors` map in `analyzer.go` — all scores come from `heuristic_scores` config.
*   **Testing**:
    *   Unit tests for `HighFrequencyDeployer` added in `main_test.go`.
    *   Unit tests for `HiddenMint`, `BurstMint`, and `SelfAllocation` added in `analyzer_test.go`.

### Frontend (`index.html`, `whitepaper.md`, `README.md`)
*   **UI/UX Improvements**:
    *   HTML syntax errors and typos in `index.html` fixed.
    *   "Copy to Clipboard" functionality with visual feedback and tooltips added for donation addresses.
    *   Social media links in the footer verified.
*   **Documentation Synchronization**:
    *   `index.html` and `whitepaper.md` updated to reflect newly implemented heuristics (`Shadowing`, `BurstMint`, `SelfAllocation`, `FrontRunning`, `GasTokenMinting`, `TxOriginPhishing`, `FlashLoanReceiver`).
    *   Risk score range (0-999) is consistent across `whitepaper.md` and `index.html`.
    *   `README.md` updated with missing heuristics and corrected Markdown link syntax.
*   **Whitepaper Enhancements**:
    *   `whitepaper.md` now includes a "Value Proposition" section, emphasizing institutional readiness and explainable intelligence.
    *   A new "Graph Explorer Architecture" section has been added to `whitepaper.md`.
    *   The whitepaper modal in `index.html` dynamically loads content from `whitepaper.md` using `marked.js`, with custom CSS for Markdown elements and automatic header ID generation for anchor links.

## Remaining Tasks:

1.  ~~**Refine `main.go` RPC Watchdog Configuration**:~~
    *   → **DONE**: Extracted to `rpc_watchdog_interval` and `rpc_stalled_threshold`.

2.  ~~**Implement "Flash-Minting" Behavioral Heuristic**:~~
    *   ~~This requires a more significant architectural change to `main.go`'s event processing pipeline to enable multi-log correlation within a single transaction receipt.~~
    *   → **DONE**: Implemented via a combined Transfer+FlashLoan subscription with per-tx log buffering. Detects when a mint (Transfer-from-zero) and FlashLoan coexist in the same tx. Configurable via `flash_mint_score`. Metric `eth_watcher_flashmints_detected_total` added.

3.  ~~**Documentation for New Configuration Parameters**:~~
    *   → **DONE**: Added Configuration Reference table to `README.md`.

4.  ~~**Code Cleanup and Refinement**:~~
     *   ~~→ **DONE**: Removed dead `score` field from `selectors` map in `analyzer.go`. Deployer history pruning now uses dedicated `high_frequency_window` config. `NewContractBaseScore` verified applied on both cache-hit and cache-miss paths.~~

5.  ~~**Configurable Event Scores** (New):~~
     *   ~~→ **DONE**: Event handlers in `main.go` now read scores from `event_scores` config section instead of hardcoded values. Defaults: MintDetected=40, MintPerMint=15, MintToDeployer=15, WhaleTransfer=25, LiquidityCreated=25, TradingDetected=20, FlashLoanDetected=50, ApprovalDetected=10, InfiniteApproval=40, LargeApproval=20, OwnershipTransferred=10, OwnershipRenounced=40.


This `@TODO.md` will serve as the primary guide for the next agent.