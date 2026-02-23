package checks

import (
	"bytes"
	"eth-watch/pkg/analyzer"
)

type OpcodeCheck struct{}

func (c *OpcodeCheck) Name() string { return "Opcodes" }

func (c *OpcodeCheck) Accumulate(ctx *analyzer.ScanContext, emit func(string, int)) {
	if ctx.PC == -1 {
		return
	}

	Op := ctx.Op
	switch Op {
	case 0x01, 0x03: // ADD, SUB
		emit("_prop:HasAddSubMul", 0)
		if Op == 0x03 && ctx.LastOp >= 0x60 && ctx.LastOp <= 0x7F {
			emit("_prop:HasSubConstant", 0)
		}
	case 0x02: // MUL
		emit("_prop:HasAddSubMul", 0)
		if ctx.LastDivPC != -1 && ctx.PC-ctx.LastDivPC < 12 {
			emit("_prop:HasDivBeforeMul", 0)
		}
	case 0x04: // DIV
		emit("_prop:HasDiv", 0)
		ctx.LastDivPC = ctx.PC
	case 0x1B, 0x1C, 0x1D: // SHL, SHR, SAR
		emit("BitwiseLogic", 5)
	case 0x16: // AND
		emit("_prop:HasAnd", 0)
	case 0x10, 0x11, 0x12, 0x13, 0x14: // LT, GT, SLT, SGT, EQ
		if Op == 0x14 {
			emit("_prop:HasEq", 0)
		}
		if ctx.LastTimestampPC != -1 && ctx.PC-ctx.LastTimestampPC < 15 {
			emit("BlockTimestampManipulation", 10)
		}
	case 0x15: // ISZERO
		emit("_prop:HasIsZero", 0)
	case 0x31: // BALANCE
		if ctx.PC+1 < len(ctx.Code) && ctx.Code[ctx.PC+1] == 0x14 {
			emit("StrictBalanceEquality", 10)
		}
	case 0x35: // CALLDATALOAD
		emit("_prop:HasCalldataLoad", 0)
	case 0x38: // COESIZE
		if !ctx.Detected["_prop:HasCodeSize"] {
			emit("_prop:HasCodeSize", 0)
			emit("SuspiciousCodeSize", 5)
		}
	case 0x3D: // RETURNDATASIZE
		emit("_prop:HasReturnDataSize", 0)
	case 0x42: // TIMESTAMP
		if !ctx.Detected["_prop:HasTimestamp"] {
			emit("_prop:HasTimestamp", 0)
			emit("TimestampDependence", 5)
		}
		ctx.LastTimestampPC = ctx.PC
	case 0x32: // ORIGIN
		if !ctx.Detected["_prop:HasOrigin"] {
			emit("_prop:HasOrigin", 0)
			emit("TxOrigin", 10)
		}
		ctx.LastOriginPC = ctx.PC
	case 0x33: // CALLER
		emit("_prop:HasCaller", 0)
	case 0x30: // ADDRESS
		emit("_prop:HasAddress", 0)
	case 0x54: // SLOAD
		if ctx.LastStaticCallPC != -1 && ctx.PC-ctx.LastStaticCallPC < 10 {
			emit("ReadOnlyReentrancy", 30)
		}
		if ctx.LastOp == 0x5F || (ctx.LastOp == 0x60 && len(ctx.PushData) == 1 && ctx.PushData[0] == 0) {
			emit("UninitializedLocalVariables", 20)
		}
		if ctx.LastOp >= 0x60 && ctx.LastOp <= 0x7F {
			slot := analyzer.BytesToInt(ctx.PushData)
			ctx.ReadSlots[slot] = true
			if !ctx.WrittenSlots[slot] {
				emit("UninitializedState", 20)
			}
		}
	case 0x55: // SSTORE
		emit("_prop:HasSstore", 0)
		if ctx.LastOp == 0x35 {
			emit("ArbitraryStorageWrite", 30)
		}
		if ctx.LastOp == 0x60 && len(ctx.PushData) == 1 && ctx.PushData[0] == 0 {
			emit("_prop:HasWriteToSlotZero", 0)
			emit("WriteToSlotZero", 20)
			emit("UninitializedPointer", 20)
		}
		if ctx.LastOp >= 0x60 && ctx.LastOp <= 0x7F {
			slot := analyzer.BytesToInt(ctx.PushData)
			ctx.WrittenSlots[slot] = true
		}
	case 0x51, 0x52, 0x53: // MLOAD, MSTORE, MSTORE8
		if ctx.LastOp == 0x54 {
			emit("AssemblyErrorProne", 20)
		}
	case 0x59: // MSIZE
		emit("AssemblyErrorProne", 10)
	case 0x50: // POP
		if ctx.LastOp == 0x54 {
			emit("_prop:HasShadowing", 0)
		}
	case 0x5A: // GAS
		if !ctx.Detected["_prop:HasGas"] {
			emit("_prop:HasGas", 0)
			emit("GasUsage", 5)
		}
	case 0x3A: // GASPRICE
		emit("GasPriceCheck", 5)
	case 0x3B: // EXTCODESIZE
		emit("AntiContractCheck", 10)
	case 0x3F: // EXTCODEHASH
		emit("CodeHashCheck", 10)
	case 0x41: // COINBASE
		emit("CoinbaseCheck", 5)
	case 0x43: // NUMBER
		emit("BlockNumberCheck", 5)
	case 0x44: // DIFFICULTY
		emit("WeakRandomness", 10)
	case 0x45: // GASLIMIT
		emit("_prop:HasGasLimit", 0)
		emit("BlockStuffing", 5)
	case 0x46: // CHAINID
		emit("ChainIDCheck", 5)
	case 0x47: // SELFBALANCE
		emit("CheckOwnBalance", 5)
	case 0x40: // BLOCKHASH
		emit("BadRandomness", 15)
	case 0x36: // CALLDATASIZE
		emit("CalldataSizeCheck", 5)
	case 0xF0: // CREATE
		emit("ContractFactory", 10)
		if ctx.PC+1 < len(ctx.Code) && ctx.Code[ctx.PC+1] == 0x50 {
			emit("UncheckedCreate", 20)
		}
		emit("_prop:CanSendEth", 0)
	case 0xF5: // CREATE2
		emit("Metamorphic", 30)
		if ctx.PC+1 < len(ctx.Code) && ctx.Code[ctx.PC+1] == 0x50 {
			emit("UncheckedCreate", 20)
		}
		emit("_prop:CanSendEth", 0)
	case 0xFF: // SELFDESTRUCT
		emit("SelfDestruct", 50)
		if ctx.LastOp == 0x73 {
			emit("HardcodedSelfDestruct", 50)
		}
		emit("_prop:CanSendEth", 0)
	case 0xF4: // DELEGATECALL
		emit("DelegateCall", 20)
		if ctx.LastOp == 0x73 {
			emit("SuspiciousDelegate", 30)
		}
		if ctx.LastOp == 0x5F || (ctx.LastOp == 0x60 && len(ctx.PushData) == 1 && ctx.PushData[0] == 0) {
			emit("DelegateCallToZero", 30)
		}
		if ctx.PC+1 < len(ctx.Code) && (ctx.Code[ctx.PC+1] == 0x50 || ctx.Code[ctx.PC+1] == 0x00) {
			emit("UncheckedDelegateCall", 20)
			emit("UncheckedCall", 15)
		}
		emit("_prop:CanSendEth", 0)
	case 0xFA: // STATICCALL
		ctx.LastStaticCallPC = ctx.PC
		if ctx.LastOp == 0x60 && len(ctx.PushData) == 1 && ctx.PushData[0] == 1 {
			emit("_prop:HasEcrecover", 0)
			emit("UncheckedEcrecover", 20)
		}
		if ctx.PC+1 < len(ctx.Code) && (ctx.Code[ctx.PC+1] == 0x50 || ctx.Code[ctx.PC+1] == 0x00) {
			emit("UncheckedCall", 15)
		}
		emit("_prop:CanSendEth", 0)
	case 0xF1, 0xF2: // CALL, CALLCODE
		if ctx.PC+1 < len(ctx.Code) && (ctx.Code[ctx.PC+1] == 0x50 || ctx.Code[ctx.PC+1] == 0x00) {
			emit("UncheckedCall", 15)
			if Op == 0xF1 && ctx.LastOp >= 0x60 && ctx.LastOp <= 0x7F {
				if ctx.LastOp == 0x61 && bytes.Equal(ctx.PushData, []byte{0x08, 0xfc}) {
					emit("UncheckedSend", 20)
				} else {
					emit("UncheckedLowLevelCall", 20)
				}
			}
			if ctx.LastSelectorPC != -1 && ctx.PC-ctx.LastSelectorPC < 30 {
				switch ctx.LastSelector {
				case analyzer.TransferSig:
					emit("UncheckedTransfer", 20)
				case analyzer.TransferFromSig:
					emit("UncheckedTransferFrom", 20)
				}
			}
		}
		if ctx.LastOriginPC != -1 && ctx.PC-ctx.LastOriginPC < 20 {
			emit("TxOriginPhishing", 50)
		}
		if Op == 0xF1 && ctx.LastOp == 0x5A {
			emit("_prop:HasGasBeforeCall", 0)
		}
		if ctx.LastOp >= 0x60 && ctx.LastOp <= 0x7F {
			if !ctx.Detected["HardcodedGasLimit"] {
				emit("HardcodedGasLimit", 5)
			}
		}
		emit("LowLevelCall", 10)
		emit("_prop:CanSendEth", 0)
		if ctx.LastOp < 0x60 || ctx.LastOp > 0x7F {
			emit("_prop:HasDynamicCall", 0)
		}
	case 0xFD: // REVERT
		emit("_prop:HasRevert", 0)
	case 0xF3: // RETURN
		emit("_prop:HasReturn", 0)
	case 0xFE: // INVALID
		emit("_prop:HasInvalid", 0)
	case 0x00: // STOP
		emit("_prop:HasStop", 0)
	case 0x20: // KECCAK256
		emit("_prop:HasKeccak256", 0)
	}
}

func (c *OpcodeCheck) Finalize(ctx *analyzer.ScanContext, emit func(string, int)) {
	if !ctx.Detected["_prop:HasSstore"] {
		emit("Stateless", 30)
	}
	if ctx.Detected["_prop:CanSendEth"] && !ctx.Detected["_prop:HasReturnDataSize"] {
		emit("UncheckedReturnData", 10)
	}
	if !ctx.Detected["_prop:CanSendEth"] {
		emit("LockedEther", 5)
	}
	if ctx.Detected["_prop:HasShadowing"] {
		emit("ShadowingState", 5)
	}
	if ctx.CountSstore > 0 && ctx.CountSload == 0 {
		emit("SuspiciousStateChange", 10)
	}
	if ctx.Detected["_prop:HasInvalid"] {
		emit("GasGriefing", 30)
	}
	if ctx.Detected["_prop:HasRevert"] && !ctx.Detected["_prop:HasReturn"] && !ctx.Detected["_prop:HasStop"] && ctx.CountSelfDestructs == 0 {
		emit("ReturnBomb", 50)
	}
}

func (c *OpcodeCheck) Reset() {}
