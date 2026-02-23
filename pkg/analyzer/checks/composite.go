package checks

import (
	"eth-watch/pkg/analyzer"
)

type CompositeCheck struct{}

func (c *CompositeCheck) Name() string { return "Composite" }

func (c *CompositeCheck) Accumulate(ctx *analyzer.ScanContext, emit func(string, int)) {
	if ctx.PC == -1 {
		return
	}
	if ctx.Op >= 0xA0 && ctx.Op <= 0xA4 { // LOG
		if ctx.Detected["_prop:HasTransferEvent"] && ctx.LastOp == 0x60 && len(ctx.PushData) == 1 && ctx.PushData[0] == 0 {
			if !ctx.Detected["Burnable"] {
				emit("ZeroAddressTransfer", 10)
			}
		}
	}
}

func (c *CompositeCheck) Finalize(ctx *analyzer.ScanContext, emit func(string, int)) {
	hasOwnable := ctx.Detected["Ownable"]
	hasBurnable := ctx.Detected["Burnable"]
	hasUpgradable := ctx.Detected["Upgradable"]
	hasWithdrawal := ctx.Detected["Withdrawal"]

	if hasBurnable && !hasOwnable {
		emit("PublicBurn", 30)
	}
	if hasUpgradable && !hasOwnable {
		emit("UnprotectedUpgrade", 40)
	}
	if ctx.CountSelfDestructs > 0 && !hasOwnable {
		emit("SelfDestructNoOwner", 30)
	}
	if hasWithdrawal && !ctx.Detected["_prop:CanSendEth"] {
		emit("PhantomFunction", 40)
	}
	if hasWithdrawal && (ctx.Detected["_prop:HasRevert"] || ctx.Detected["_prop:HasInvalid"] || ctx.CountDelegateCalls > 0) {
		emit("StrawManContract", 50)
	}
	if hasWithdrawal && ctx.Detected["_prop:CanSendEth"] && ctx.CountSload == 0 {
		emit("UnprotectedEtherWithdrawal", 40)
	}

	isTokenLike := ctx.Detected["_prop:HasTransferSig"] || ctx.Detected["Mintable"] || hasBurnable
	if isTokenLike && !ctx.Detected["_prop:HasSstore"] {
		emit("FakeToken", 50)
	}
	if ctx.Detected["_prop:HasTransferSig"] && ctx.Detected["_prop:HasDiv"] {
		emit("TaxToken", 20)
	}
	if ctx.Detected["_prop:HasTransferSig"] && !ctx.Detected["_prop:HasTransferEvent"] {
		emit("NoTransferEvent", 20)
		if ctx.Detected["_prop:HasSstore"] {
			emit("PotentialHoneypot", 50)
		}
	}
	if ctx.Detected["_prop:HasTransferSig"] && !ctx.Detected["Mintable"] && ctx.Detected["_prop:HasSstore"] && ctx.Detected["_prop:HasCaller"] && ctx.Detected["_prop:HasAddSubMul"] {
		emit("HiddenMint", 40)
	}

	if ctx.Detected["_prop:HasKeccak256"] && ctx.Detected["_prop:HasEq"] && ctx.CountSload > 0 {
		emit("FrontRunning", 30)
	}
	if ctx.Detected["_prop:HasEcrecover"] && !ctx.Detected["_prop:HasSValueCheck"] {
		emit("SignatureMalleability", 20)
	}
	if ctx.CountSelfDestructs > 0 && ctx.CountCreates > 0 {
		emit("GasTokenMinting", 40)
	}
	if ctx.Detected["_prop:HasTransferSig"] && !ctx.Detected["_prop:HasIsZero"] && !ctx.Detected["_prop:HasEq"] {
		emit("MissingZeroCheck", 10)
	}
	if ctx.Detected["_prop:HasCaller"] && ctx.Detected["_prop:HasSstore"] && ctx.CountSload == 0 {
		emit("UninitializedConstructor", 30)
	}
	if !ctx.Detected["_prop:HasSstore"] && ctx.Detected["_prop:HasBalanceOf"] {
		emit("FakeHighBalance", 40)
	}
	if ctx.Detected["_prop:HasTransferSig"] && ctx.Detected["_prop:HasSubConstant"] {
		emit("HiddenFee", 20)
	}
	if ctx.Detected["ApprovalFunction"] && !ctx.Detected["_prop:HasTransferSig"] {
		emit("HiddenApproval", 20)
	}
	if ctx.Detected["_prop:HasTransferSig"] && ctx.Detected["_prop:HasTimestamp"] {
		emit("TradingCooldown", 10)
	}
	if ctx.Detected["_prop:HasTransferSig"] && ctx.Detected["_prop:HasCaller"] {
		emit("OwnerTransferCheck", 5)
	}
	if ctx.Detected["_prop:HasTransferEvent"] && !ctx.Detected["_prop:HasSstore"] {
		emit("FakeTransferEvent", 50)
	}
	if ctx.CountSelfDestructs > 0 && ctx.Detected["_prop:HasCaller"] {
		emit("PrivilegedSelfDestruct", 20)
	}
	if ctx.CountSelfDestructs > 0 && ((!ctx.Detected["_prop:HasCaller"] && !ctx.Detected["_prop:HasOrigin"]) || (!ctx.Detected["_prop:HasEq"] && !ctx.Detected["_prop:HasIsZero"])) {
		emit("UnprotectedSelfDestruct", 50)
	}
	if (ctx.Detected["_prop:HasTransferSig"] || ctx.Detected["_prop:HasBalanceOf"]) && !ctx.Detected["_prop:HasReturn"] {
		emit("MissingReturn", 20)
	}
	if ctx.CountDelegateCalls > 0 && ctx.CountSelfDestructs > 0 {
		emit("ProxyDestruction", 30)
	}
	if ctx.CountCreates > 0 && ctx.CountSelfDestructs > 0 {
		emit("MetamorphicExploit", 30)
	}
	if ctx.CountDelegateCalls > 0 && ctx.Detected["_prop:HasAddress"] {
		emit("DelegateCallToSelf", 30)
	}
	if ctx.CountDelegateCalls > 0 && ctx.Detected["_prop:HasCalldataLoad"] {
		emit("UnsafeDelegateCall", 20)
	}
	if ctx.CountDelegateCalls > 0 && !ctx.Detected["HardcodedGasLimit"] {
		emit("UnrestrictedDelegateCall", 30)
	}
	if ctx.Detected["_prop:HasAnd"] && ctx.Detected["_prop:HasCalldataLoad"] {
		emit("IntegerTruncation", 10)
	}
	if ctx.Detected["LoopDetected"] && (ctx.Detected["HardcodedGasLimit"] || ctx.Detected["_prop:HasGasLimit"]) {
		emit("DoSGasLimit", 15)
	}
	if ctx.Detected["_prop:HasGasBeforeCall"] && !ctx.Detected["ReentrancyGuard"] {
		emit("ReentrancyNoGasLimit", 30)
	}
	if ctx.Detected["_prop:HasAddSubMul"] && !ctx.Detected["_prop:HasPanic"] {
		emit("UncheckedMath", 10)
	}
	if ctx.Detected["_prop:HasDivBeforeMul"] {
		emit("DivideBeforeMultiply", 10)
	}
	if ctx.Detected["_prop:HasEcrecover"] && ctx.CountSload == 0 {
		emit("SignatureReplay", 20)
	}
	if ctx.Detected["_prop:HasDynamicCall"] && ctx.Detected["_prop:HasCalldataLoad"] {
		emit("TokenDraining", 30)
	}
}

func (c *CompositeCheck) Reset() {}
