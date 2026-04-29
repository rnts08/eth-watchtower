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
    *   High-frequency deployer parameters (`high_frequency_threshold`, `high_frequency_score`) are configurable.
    *   Base score for new contracts (`new_contract_base_score`) and maximum risk score (`max_risk_score`) are configurable.
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

1.  **Refine `main.go` RPC Watchdog Configuration**:
    *   The `startWatchdog` function still uses hardcoded `60*time.Second` for `stalledRPCThreshold` and `10*time.Second` for `watchdogInterval`. These should be moved to `config.json` for full configurability.

2.  **Implement "Flash-Minting" Behavioral Heuristic**:
    *   This requires a more significant architectural change to `main.go`'s event processing pipeline to enable multi-log correlation within a single transaction receipt. The current handlers process logs individually. A new mechanism is needed to collect all logs for a transaction and then apply "Flash-Minting" detection logic.

3.  **Documentation for New Configuration Parameters**:
    *   Update `README.md` and potentially `whitepaper.md` to document the newly added configurable parameters in `config.json` (e.g., `max_rpc_failures`, `rpc_trip_duration`, `max_code_cache_size`, `high_frequency_threshold`, `high_frequency_score`, `new_contract_base_score`, `max_risk_score`, `heuristic_scores`).

4.  **Code Cleanup and Refinement**:
    *   Review `analyzer.go` for any remaining hardcoded scores that might have been missed in the refactoring.
    *   Ensure consistent logging practices across `main.go` and `analyzer.go`.
    *   Consider adding more detailed comments where complex logic is present.


This `@TODO.md` will serve as the primary guide for the next agent.