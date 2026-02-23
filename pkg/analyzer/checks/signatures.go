package checks

import (
	"bytes"
	"eth-watch/pkg/analyzer"
)

type SignaturesCheck struct {
	hasEIP1967 bool
	hasEIP1822 bool
	hasEIP1167 bool
	hasERC1820 bool
}

func (c *SignaturesCheck) Name() string { return "Signatures" }

func (c *SignaturesCheck) Accumulate(ctx *analyzer.ScanContext, emit func(string, int)) {
	if ctx.PC == -1 {
		if bytes.HasPrefix(ctx.Code, analyzer.Eip1167Prefix) {
			c.hasEIP1167 = true
			emit("MinimalProxy", 0)
		}
		return
	}

	if ctx.Op == 0x60 && bytes.HasPrefix(ctx.Code[ctx.PC:], analyzer.FakeReturnSig) {
		emit("FakeReturn", 20)
	}

	if ctx.Op >= 0x60 && ctx.Op <= 0x7F {
		if len(ctx.PushData) >= 4 {
			var sig [4]byte
			copy(sig[:], ctx.PushData)
			ctx.LastSelector = sig
			ctx.LastSelectorPC = ctx.PC

			if sig == analyzer.TransferSig {
				emit("_prop:HasTransferSig", 0)
			} else if sig == analyzer.BalanceOfSig {
				emit("_prop:HasBalanceOf", 0)
			} else if sig == [4]byte{0x4e, 0x48, 0x7b, 0x71} {
				emit("_prop:HasPanic", 0)
			} else if val, ok := analyzer.Selectors[sig]; ok {
				emit(val.Flag, val.Score)
			}
		}

		if ctx.Op == 0x73 { // PUSH20
			if bytes.Equal(ctx.PushData, analyzer.TornadoRouter) {
				emit("HardcodedBlacklistedAddress", 50)
			} else if bytes.Equal(ctx.PushData, analyzer.Erc1820Addr) {
				c.hasERC1820 = true
			}
		}
		if ctx.Op == 0x7F { // PUSH32
			if bytes.Equal(ctx.PushData, analyzer.TransferEventTopic) {
				emit("_prop:HasTransferEvent", 0)
			}
			if bytes.Equal(ctx.PushData, analyzer.Eip1967Impl) || bytes.Equal(ctx.PushData, analyzer.Eip1967Admin) {
				c.hasEIP1967 = true
			}
			if bytes.Equal(ctx.PushData, analyzer.Eip1822Slot) {
				c.hasEIP1822 = true
			}
		}
		if bytes.Contains(ctx.PushData, []byte("ReentrancyGuard")) {
			emit("ReentrancyGuard", 0)
		}
		if len(ctx.PushData) == 32 && ctx.PushData[0] == 0x7f && ctx.PushData[1] == 0xff {
			emit("_prop:HasSValueCheck", 0)
		}
	}
}

func (c *SignaturesCheck) Finalize(ctx *analyzer.ScanContext, emit func(string, int)) {
	if c.hasERC1820 {
		emit("ERC777Reentrancy", 20)
	}
	if ctx.Detected["_prop:HasTransferEvent"] && ctx.CountLogs == 0 {
		emit("TransferTopicWithoutLogs", 10)
	}
	if ctx.Detected["_prop:HasTransferEvent"] && !ctx.Detected["_prop:HasTransferSig"] {
		emit("MisleadingFunctionName", 20)
	}
	if ctx.CountDelegateCalls > 0 && !c.hasEIP1967 && !c.hasEIP1822 && !c.hasEIP1167 {
		emit("NonStandardProxy", 20)
	}
	if ctx.CountDelegateCalls > 0 && len(ctx.Detected) > 1 {
		if ctx.Detected["_prop:HasTransferSig"] || ctx.Detected["Mintable"] {
			emit("ProxySelectorClash", 15)
		}
	}
}

func (c *SignaturesCheck) Reset() { *c = SignaturesCheck{} }
