package checks

import (
	"bytes"
	"eth-watch/pkg/analyzer"
)

// RugpullCheck looks for specific scam patterns like "Liquidity Lock" or "Renounced Ownership"
// combined with suspicious functions.
type RugpullCheck struct{}

func (c *RugpullCheck) Name() string { return "Rugpull" }

func (c *RugpullCheck) Accumulate(ctx *analyzer.ScanContext, emit func(string, int)) {
	if ctx.PC == -1 {
		return
	}

	// Example: Look for hardcoded addresses in a suspicious context (e.g. transfer destination)
	if ctx.Op == 0x73 { // PUSH20
		// If we see a hardcoded address being pushed, it might be a fee collector or dev wallet
		// This is just a demonstration of a modular check.
		if bytes.HasPrefix(ctx.PushData, []byte{0xde, 0xad, 0xbe, 0xef}) {
			emit("SuspiciousDevWallet", 30)
		}
	}
}

func (c *RugpullCheck) Finalize(ctx *analyzer.ScanContext, emit func(string, int)) {
	// If the contract has 'Blacklist' functionality but NO 'Ownable' logic, it's very risky.
	if ctx.Detected["Blacklist"] && !ctx.Detected["Ownable"] {
		emit("UnprotectedBlacklist", 50)
		emit("RugpullPotential", 40)
	}

	// If it has 'Mintable' but 'RenounceOwnership' is missing, dev can mint forever.
	if ctx.Detected["Mintable"] && !ctx.Detected["RenounceOwnership"] {
		emit("InfiniteMintPotential", 20)
	}
}

func (c *RugpullCheck) Reset() {}
