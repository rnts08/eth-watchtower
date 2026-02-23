# Analyzer Modules (Checks)

This directory contains individual security checks for the Ethereum Watchtower. The analyzer uses a modular architecture where each check implements the `Check` interface.

## How to Write a New Check

1.  **Create a new file**: Add a `.go` file in this directory (e.g., `scam_detector.go`).
2.  **Define your struct**: Implement the `Check` interface.

```go
type MyNewCheck struct {
    // any internal state for this scan
}

func (c *MyNewCheck) Name() string { return "MyScan" }

func (c *MyNewCheck) Accumulate(ctx *analyzer.ScanContext, emit func(string, int)) {
    // Called for every opcode.
    // ctx.Op contains the current opcode.
    // ctx.PC contains the current Program Counter.
    // Use ctx.PC == -1 for pre-scan (initialization).
}

func (c *MyNewCheck) Finalize(ctx *analyzer.ScanContext, emit func(string, int)) {
    // Called after the entire bytecode has been scanned.
    // Use this for cross-check logic (e.g., if A and B were seen).
}

func (c *MyNewCheck) Reset() {
    // Reset state for a new scan.
}
```

3.  **Register your check**: Add your check to the `DefaultCheckSet()` function in `defaults.go`.

```go
cs.Register(&MyNewCheck{})
```

## ScanContext and Communication

Checks can communicate with each other using the `ctx.Detected` map and internal property flags (prefixed with `_prop:`).

-   `_prop:HasTransferSig`: Seen a transfer selector.
-   `_prop:CanSendEth`: Seen an opcode that can send ETH (CALL, SELFDESTRUCT, etc).
-   `_prop:HasSstore`: Contract has state modifications.

Example:
```go
if ctx.Detected["_prop:HasTransferSig"] && !ctx.Detected["_prop:HasTransferEvent"] {
    emit("HiddenTransfer", 30)
}
```

## Best Practices

-   **KISS**: Keep individual checks simple and focused.
-   **No Placeholders**: Use real bytecode patterns or signatures.
-   **Internal Flags**: Prefix temporary state flags with `_prop:` to avoid polluting the final finding list.
-   **Weighted Scores**: Use reasonable scores (1-100) based on severity.
