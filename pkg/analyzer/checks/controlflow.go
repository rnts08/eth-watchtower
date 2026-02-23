package checks

import (
	"eth-watch/pkg/analyzer"
)

type ControlFlowCheck struct {
	isUnreachable bool
	hasDeadCode   bool
}

func (c *ControlFlowCheck) Name() string { return "ControlFlow" }

func (c *ControlFlowCheck) Accumulate(ctx *analyzer.ScanContext, emit func(string, int)) {
	if ctx.PC == -1 {
		return
	}
	if c.isUnreachable && ctx.Op != 0x5B {
		if !c.hasDeadCode {
			c.hasDeadCode = true
			emit("DeadCode", 5)
		}
	}
	if ctx.Op == 0x5B {
		c.isUnreachable = false
	}

	switch ctx.Op {
	case 0x56, 0x57: // JUMP, JUMPI
		if ctx.LastOp >= 0x60 && ctx.LastOp <= 0x7F {
			dest := analyzer.BytesToInt(ctx.PushData)
			if snap, exists := ctx.JumpDests[dest]; exists {
				emit("LoopDetected", 5)
				if ctx.Op == 0x56 {
					emit("InfiniteLoop", 20)
					emit("GasGriefingLoop", 30)
				}
				if ctx.CountCalls > snap.CountCalls {
					emit("CallInLoop", 10)
				}
				if ctx.CountDelegateCalls > snap.CountDelegateCalls {
					emit("DelegateCallInLoop", 20)
				}
				if ctx.CountCreates > snap.CountCreates {
					emit("FactoryInLoop", 15)
				}
				if ctx.CountSelfDestructs > snap.CountSelfDestructs {
					emit("SelfDestructInLoop", 50)
				}
				if ctx.CountGasOps > snap.CountGasOps {
					emit("GasDependentLoop", 10)
					emit("GasGriefing", 30)
					emit("GasGriefingLoop", 30)
				}
				if ctx.CountSstore > snap.CountSstore {
					emit("CostlyLoop", 10)
				}
			}
		} else {
			emit("ArbitraryJump", 40)
		}
	case 0xFD, 0xF3, 0xFE, 0x00: // terminators
		c.isUnreachable = true
	}
}

func (c *ControlFlowCheck) Finalize(ctx *analyzer.ScanContext, emit func(string, int)) {
}

func (c *ControlFlowCheck) Reset() { *c = ControlFlowCheck{} }
