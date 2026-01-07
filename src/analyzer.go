package main

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

// AnalyzeCode performs static analysis on contract bytecode to identify risks and features.
func AnalyzeCode(code []byte) ([]string, int) {
	return NewAnalyzer(code).Analyze()
}

type loopSnapshot struct {
	c, dc, cr, sd, g, ss int
}

type Analyzer struct {
	code []byte
	pc   int

	flags    []string
	score    int
	detected map[string]bool

	lastOp          byte
	lastPushData    []byte
	lastDivPC       int
	lastTimestampPC int
	jumpDests       map[int]loopSnapshot

	// Opcode scanning flags
	hasSelfDestruct          bool
	hasDelegateCall          bool
	hasTimestamp             bool
	hasCaller                bool
	hasAddress               bool
	hasOrigin                bool
	hasSstore                bool
	hasGasPrice              bool
	hasExtCodeSize           bool
	hasExtCodeHash           bool
	hasCoinbase              bool
	hasDifficulty            bool
	hasGasLimit              bool
	hasChainID               bool
	hasSelfBalance           bool
	hasCreate2               bool
	hasBlockNumber           bool
	hasBlockHash             bool
	hasCalldataSize          bool
	hasCreate                bool
	hasLowLevelCall          bool
	hasDiv                   bool
	hasStrictBalance         bool
	hasUncheckedCall         bool
	canSendEth               bool
	hasGas                   bool
	hasDivBeforeMul          bool
	hasShadowing             bool
	hasCodeSize              bool
	hasWriteToSlotZero       bool
	hasHardcodedGas          bool
	hasRevert                bool
	hasReturn                bool
	hasStop                  bool
	hasReturnDataSize        bool
	hasLoop                  bool
	hasInfiniteLoop          bool
	hasCallInLoop            bool
	hasDelegateCallInLoop    bool
	hasFactoryInLoop         bool
	hasSelfDestructInLoop    bool
	hasGasDependentLoop      bool
	hasSstoreInLoop          bool
	hasDelegateCallToZero    bool
	hasHardcodedSelfDestruct bool
	hasDelegateCallToSelf    bool
	hasHardcodedBlacklist    bool
	hasHardcodedDelegate     bool
	hasInvalid               bool
	hasGasBeforeCall         bool

	hasAddSubMul       bool
	hasSubConstant     bool
	hasCalldataLoad    bool
	hasPanic           bool
	hasReentrancyGuard bool
	hasStaticCall      bool
	hasAnd             bool
	isUnreachable      bool
	hasDeadCode        bool
	hasDynamicJump     bool
	hasDynamicCall     bool
	hasKeccak256       bool
	hasEq              bool
	hasIsZero          bool
	hasEcrecover       bool
	hasSValueCheck     bool

	// Special signatures
	hasTransferSig   bool
	hasBalanceOf     bool
	isMintable       bool
	hasTransferEvent bool
	hasERC1820       bool
	hasEIP1967       bool

	// Counters
	countCalls         int
	countDelegateCalls int
	countCreates       int
	countSelfDestructs int
	countGasOps        int
	countSload         int
	countSstore        int
	countLogs          int

	writtenSlots map[int]bool
	readSlots    map[int]bool

	enabledHeuristics  map[string]bool
	disabledHeuristics map[string]bool
}

func NewAnalyzer(code []byte) *Analyzer {
	return &Analyzer{
		code:            code,
		detected:        make(map[string]bool),
		jumpDests:       make(map[int]loopSnapshot),
		lastDivPC:       -1,
		lastTimestampPC: -1,
		writtenSlots:    make(map[int]bool),
		readSlots:       make(map[int]bool),
	}
}

func (a *Analyzer) Reset(code []byte) {
	// Preserve allocated maps and slices
	flags := a.flags[:0]
	detected := a.detected
	for k := range detected {
		delete(detected, k)
	}
	jumpDests := a.jumpDests
	for k := range jumpDests {
		delete(jumpDests, k)
	}
	writtenSlots := a.writtenSlots
	for k := range writtenSlots {
		delete(writtenSlots, k)
	}
	readSlots := a.readSlots
	for k := range readSlots {
		delete(readSlots, k)
	}

	*a = Analyzer{}

	a.code = code
	a.flags = flags
	a.detected = detected
	a.jumpDests = jumpDests
	a.lastDivPC = -1
	a.lastTimestampPC = -1
	a.writtenSlots = writtenSlots
	a.readSlots = readSlots
}

func (a *Analyzer) UpdateHeuristics(enabled, disabled map[string]bool) {
	a.enabledHeuristics = enabled
	a.disabledHeuristics = disabled
}

func (a *Analyzer) addFlag(flag string, s int) {
	// Check disabled first
	if len(a.disabledHeuristics) > 0 && a.disabledHeuristics[flag] {
		return
	}
	// Check enabled if present (allowlist mode)
	if len(a.enabledHeuristics) > 0 && !a.enabledHeuristics[flag] {
		return
	}
	if !a.detected[flag] {
		a.detected[flag] = true
		a.flags = append(a.flags, flag)
		a.score += s
	}
}

func (a *Analyzer) Analyze() ([]string, int) {
	// Known malicious/high-risk addresses (e.g. Tornado Cash Router)
	tornadoRouter := common.HexToAddress("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b").Bytes()

	// Function selectors map (4 bytes)
	selectors := map[[4]byte]struct {
		flag  string
		score int
	}{
		{0x40, 0xc1, 0x0f, 0x19}: {"Mintable", 10},
		{0x42, 0x96, 0x6c, 0x68}: {"Burnable", 0},
		{0xf2, 0xfd, 0xe3, 0x8b}: {"Ownable", 0},
		{0x1d, 0x3b, 0x9e, 0xdf}: {"Blacklist", 20},
		{0xfe, 0x57, 0x5a, 0x87}: {"Blacklist", 20},
		{0x36, 0x59, 0xcf, 0xe6}: {"Upgradable", 5},
		{0x01, 0xff, 0xc9, 0xa7}: {"InterfaceCheck", 0},
		{0x67, 0x34, 0x48, 0xdd}: {"IncorrectConstructor", 5},
		{0x3c, 0xcf, 0xd6, 0x0b}: {"Withdrawal", 0},
		{0x2e, 0x1a, 0x7d, 0x4d}: {"Withdrawal", 0},
		{0x71, 0x50, 0x18, 0xa6}: {"RenounceOwnership", 0},
		{0x5c, 0xff, 0xe9, 0xde}: {"FlashLoan", 0},
		{0x81, 0x29, 0xfc, 0x1c}: {"ReinitializableProxy", 20},
	}

	// Special signatures
	transferSig := [4]byte{0xa9, 0x05, 0x9c, 0xbb}
	balanceOfSig := [4]byte{0x70, 0xa0, 0x82, 0x31}
	transferFromSig := [4]byte{0x23, 0xb8, 0x72, 0xdd}

	// Fake Return Pattern: PUSH1 01 PUSH1 00 MSTORE PUSH1 20 PUSH1 00 RETURN
	// 600160005260206000f3
	fakeReturnSig := []byte{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}

	// Transfer Event Topic
	transferEventTopic := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").Bytes()

	// ERC1820 Registry Address
	erc1820Addr := common.HexToAddress("0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24").Bytes()

	// EIP-1967 Storage Slots
	eip1967Impl := common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").Bytes()
	eip1967Admin := common.HexToHash("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103").Bytes()

	var lastSelector [4]byte
	lastSelectorPC := -1

	for a.pc < len(a.code) {
		op := a.code[a.pc]

		// Check for Fake Return Pattern (PUSH1 01 ... RETURN)
		// 600160005260206000f3
		if op == 0x60 && bytes.HasPrefix(a.code[a.pc:], fakeReturnSig) {
			a.addFlag("FakeReturn", 20)
		}

		// DeadCode check: Code after terminator that isn't JUMPDEST is unreachable
		if a.isUnreachable && op != 0x5B {
			if !a.hasDeadCode {
				a.hasDeadCode = true
				a.addFlag("DeadCode", 5)
			}
		}

		// Skip PUSH data (PUSH1=0x60 ... PUSH32=0x7F)
		if op >= 0x60 && op <= 0x7F {
			pushBytes := int(op - 0x5F)
			if a.pc+1+pushBytes <= len(a.code) {
				a.lastPushData = a.code[a.pc+1 : a.pc+1+pushBytes]

				// Check signatures in PUSH data
				if len(a.lastPushData) >= 4 {
					// Check 4-byte selectors
					// We check the first 4 bytes of the push data
					var sig [4]byte
					copy(sig[:], a.lastPushData)

					lastSelector = sig
					lastSelectorPC = a.pc

					if sig == transferSig {
						a.hasTransferSig = true
					} else if sig == balanceOfSig {
						a.hasBalanceOf = true
					} else if val, ok := selectors[sig]; ok {
						a.addFlag(val.flag, val.score)
						if val.flag == "Mintable" {
							a.isMintable = true
						}
					}

					// Check Panic signature (0x4e487b71)
					if sig == [4]byte{0x4e, 0x48, 0x7b, 0x71} {
						a.hasPanic = true
					}
				}

				// Check for specific addresses and topics
				if op == 0x73 { // PUSH20
					if bytes.Equal(a.lastPushData, tornadoRouter) {
						a.hasHardcodedBlacklist = true
						a.addFlag("HardcodedBlacklistedAddress", 50)
					} else if bytes.Equal(a.lastPushData, erc1820Addr) {
						a.hasERC1820 = true
					}
					if bytes.Equal(a.lastPushData, eip1967Impl) || bytes.Equal(a.lastPushData, eip1967Admin) {
						a.hasEIP1967 = true
					}
				}
				if op == 0x7F { // PUSH32
					if bytes.Equal(a.lastPushData, transferEventTopic) {
						a.hasTransferEvent = true
					}
				}

				// Check for ReentrancyGuard string
				if bytes.Contains(a.lastPushData, []byte("ReentrancyGuard")) {
					a.hasReentrancyGuard = true
				}

				// Check for S-value constant (approximate check for half-curve order)
				if len(a.lastPushData) == 32 && a.lastPushData[0] == 0x7f && a.lastPushData[1] == 0xff {
					a.hasSValueCheck = true
				}
			} else {
				a.lastPushData = nil
			}
			a.lastOp = op
			a.pc += pushBytes + 1
			continue
		}

		if op == 0x5B { // JUMPDEST
			a.isUnreachable = false
		}

		switch op {
		case 0x01, 0x03: // ADD, SUB
			a.hasAddSubMul = true
			if op == 0x03 && a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				a.hasSubConstant = true
			}
		case 0x16: // AND
			a.hasAnd = true
		case 0x35: // CALLDATALOAD
			a.hasCalldataLoad = true
		case 0x5B: // JUMPDEST
			a.jumpDests[a.pc] = loopSnapshot{
				a.countCalls, a.countDelegateCalls, a.countCreates, a.countSelfDestructs, a.countGasOps, a.countSstore,
			}
		case 0x56, 0x57: // JUMP, JUMPI
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F { // Previous op was PUSH
				dest := bytesToInt(a.lastPushData)
				if snap, exists := a.jumpDests[dest]; exists {
					// Backward jump detected -> Loop
					if !a.hasLoop {
						a.hasLoop = true
						a.addFlag("LoopDetected", 5)
					}
					if op == 0x56 { // Unconditional backward jump
						a.hasInfiniteLoop = true
					}
					// Check what happened inside the loop
					if a.countCalls > snap.c {
						a.hasCallInLoop = true
					}
					if a.countDelegateCalls > snap.dc {
						a.hasDelegateCallInLoop = true
					}
					if a.countCreates > snap.cr {
						a.hasFactoryInLoop = true
					}
					if a.countSelfDestructs > snap.sd {
						a.hasSelfDestructInLoop = true
					}
					if a.countGasOps > snap.g {
						a.hasGasDependentLoop = true
					}
					if a.countSstore > snap.ss {
						a.hasSstoreInLoop = true
					}
				}
			} else {
				a.hasDynamicJump = true
			}
		case 0x38: // CODESIZE
			if !a.hasCodeSize {
				a.hasCodeSize = true
				a.addFlag("SuspiciousCodeSize", 5)
			}
		case 0x3D: // RETURNDATASIZE
			a.hasReturnDataSize = true
		case 0x20: // SHA3 / KECCAK256
			a.hasKeccak256 = true
		case 0x10, 0x11, 0x12, 0x13, 0x14: // LT, GT, SLT, SGT, EQ
			if op == 0x14 {
				a.hasEq = true
			}
			if a.lastTimestampPC != -1 && a.pc-a.lastTimestampPC < 15 {
				a.addFlag("BlockTimestampManipulation", 10)
			}
		case 0x15: // ISZERO
			a.hasIsZero = true
		case 0x04: // DIV
			a.hasDiv = true
			a.lastDivPC = a.pc
		case 0x02: // MUL
			a.hasAddSubMul = true
			if a.lastDivPC != -1 && a.pc-a.lastDivPC < 12 {
				a.hasDivBeforeMul = true
			}
		case 0x31: // BALANCE
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x14 { // EQ
				a.hasStrictBalance = true
			}
		case 0x54: // SLOAD
			a.countSload++
			if a.lastOp == 0xFA { // STATICCALL
				a.addFlag("ReadOnlyReentrancy", 30)
			}
			if a.lastOp == 0x5F || (a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0) {
				a.addFlag("UninitializedLocalVariables", 20)
			}
			// Track read slots (simplified: only tracks constant slots pushed immediately before)
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				slot := bytesToInt(a.lastPushData)
				a.readSlots[slot] = true
				if !a.writtenSlots[slot] {
					a.addFlag("UninitializedState", 20)
				}
			}
		case 0x51, 0x52, 0x53: // MLOAD, MSTORE, MSTORE8
			if a.lastOp == 0x54 { // SLOAD
				a.addFlag("AssemblyErrorProne", 20)
			}
		case 0x59: // MSIZE
			a.addFlag("AssemblyErrorProne", 10)
		case 0x50: // POP
			if a.lastOp == 0x54 { // SLOAD
				a.hasShadowing = true
			}
		case 0x5A: // GAS
			a.countGasOps++
			if !a.hasGas {
				a.hasGas = true
				a.addFlag("GasUsage", 5)
			}
		case 0xFF: // SELFDESTRUCT
			a.countSelfDestructs++
			if !a.hasSelfDestruct {
				a.hasSelfDestruct = true
				a.addFlag("SelfDestruct", 50)
			}
			if a.lastOp == 0x73 && !a.hasHardcodedSelfDestruct { // PUSH20 before SELFDESTRUCT
				a.hasHardcodedSelfDestruct = true
				a.addFlag("HardcodedSelfDestruct", 50)
			}
			a.canSendEth = true
		case 0xF4: // DELEGATECALL
			a.countDelegateCalls++
			if !a.hasDelegateCall {
				a.hasDelegateCall = true
				a.addFlag("DelegateCall", 20)
			}
			if a.lastOp == 0x73 { // PUSH20
				a.addFlag("SuspiciousDelegate", 30)
				a.hasHardcodedDelegate = true
			}
			if a.lastOp == 0x30 { // ADDRESS
				a.hasDelegateCallToSelf = true
			}
			// Check for DelegateCall to Zero (PUSH0 or PUSH1 0x00 before DELEGATECALL)
			if a.lastOp == 0x5F || (a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0) {
				if !a.hasDelegateCallToZero {
					a.hasDelegateCallToZero = true
					a.addFlag("DelegateCallToZero", 30)
				}
			}
			// Check for Unchecked Return (DELEGATECALL + POP)
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x50 {
				a.hasUncheckedCall = true
			}
			a.canSendEth = true
		case 0x42: // TIMESTAMP
			if !a.hasTimestamp {
				a.hasTimestamp = true
				a.addFlag("TimestampDependence", 5)
			}
			a.lastTimestampPC = a.pc
		case 0x33: // CALLER (msg.sender)
			a.hasCaller = true
		case 0x30: // ADDRESS
			a.hasAddress = true
		case 0x32: // ORIGIN
			if !a.hasOrigin {
				a.hasOrigin = true
				a.addFlag("TxOrigin", 10)
			}
		case 0x55: // SSTORE
			a.hasSstore = true
			a.countSstore++
			if a.lastOp == 0x35 { // CALLDATALOAD
				a.addFlag("ArbitraryStorageWrite", 30)
			}
			if a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0 {
				if !a.hasWriteToSlotZero {
					a.hasWriteToSlotZero = true
					a.addFlag("WriteToSlotZero", 20)
				}
			}
			// Track written slots
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				slot := bytesToInt(a.lastPushData)
				a.writtenSlots[slot] = true
			}
		case 0x3A: // GASPRICE
			if !a.hasGasPrice {
				a.hasGasPrice = true
				a.addFlag("GasPriceCheck", 5)
			}
		case 0x3B: // EXTCODESIZE
			if !a.hasExtCodeSize {
				a.hasExtCodeSize = true
				a.addFlag("AntiContractCheck", 10)
			}
		case 0x3F: // EXTCODEHASH
			if !a.hasExtCodeHash {
				a.hasExtCodeHash = true
				a.addFlag("CodeHashCheck", 10)
			}
		case 0x41: // COINBASE
			if !a.hasCoinbase {
				a.hasCoinbase = true
				a.addFlag("CoinbaseCheck", 5)
			}
		case 0x43: // NUMBER
			if !a.hasBlockNumber {
				a.hasBlockNumber = true
				a.addFlag("BlockNumberCheck", 5)
			}
		case 0x44: // DIFFICULTY (PREVRANDAO)
			if !a.hasDifficulty {
				a.hasDifficulty = true
				a.addFlag("WeakRandomness", 10)
			}
		case 0x45: // GASLIMIT
			if !a.hasGasLimit {
				a.hasGasLimit = true
				a.addFlag("BlockStuffing", 5)
			}
		case 0x46: // CHAINID
			if !a.hasChainID {
				a.hasChainID = true
				a.addFlag("ChainIDCheck", 5)
			}
		case 0x47: // SELFBALANCE
			if !a.hasSelfBalance {
				a.hasSelfBalance = true
				a.addFlag("CheckOwnBalance", 5)
			}
		case 0xF5: // CREATE2
			if !a.hasCreate2 {
				a.hasCreate2 = true
				a.addFlag("Metamorphic", 30)
			}
			a.countCreates++
			a.canSendEth = true
		case 0x40: // BLOCKHASH
			if !a.hasBlockHash {
				a.hasBlockHash = true
				a.addFlag("BadRandomness", 15)
			}
		case 0x36: // CALLDATASIZE
			if !a.hasCalldataSize {
				a.hasCalldataSize = true
				a.addFlag("CalldataSizeCheck", 5)
			}
		case 0xF0: // CREATE
			a.countCreates++
			if !a.hasCreate {
				a.hasCreate = true
				a.addFlag("ContractFactory", 10)
			}
			a.canSendEth = true
		case 0xFA: // STATICCALL
			a.hasStaticCall = true
			if a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 1 {
				a.hasEcrecover = true
				a.addFlag("UncheckedEcrecover", 20)
			}
			// Check for Unchecked Return (STATICCALL + POP)
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x50 {
				a.hasUncheckedCall = true
			}
			a.canSendEth = true
		case 0xF1, 0xF2: // CALL, CALLCODE
			a.countCalls++
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x50 { // CALL/CALLCODE + POP
				a.hasUncheckedCall = true
				if lastSelectorPC != -1 && a.pc-lastSelectorPC < 30 && (lastSelector == transferSig || lastSelector == transferFromSig) {
					a.addFlag("UncheckedTransfer", 20)
				}
			}
			if op == 0xF1 && a.lastOp == 0x5A { // GAS + CALL
				a.hasGasBeforeCall = true
			}
			// Check for Hardcoded Gas Limit (PUSH + CALL)
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				if !a.hasHardcodedGas {
					a.hasHardcodedGas = true
					a.addFlag("HardcodedGasLimit", 5)
				}
			}
			if !a.hasLowLevelCall {
				a.hasLowLevelCall = true
				a.addFlag("LowLevelCall", 10)
			}
			if !(a.lastOp >= 0x60 && a.lastOp <= 0x7F) {
				a.hasDynamicCall = true
			}
			a.canSendEth = true
		case 0xFD: // REVERT
			a.hasRevert = true
			a.isUnreachable = true
		case 0xF3: // RETURN
			a.hasReturn = true
			a.isUnreachable = true
		case 0xFE: // INVALID
			a.hasInvalid = true
			a.isUnreachable = true
		case 0x00: // STOP
			a.hasStop = true
			a.isUnreachable = true
		case 0xA0, 0xA1, 0xA2, 0xA3, 0xA4: // LOG0 - LOG4
			a.countLogs++
			// Heuristic for ZeroAddressTransfer: Transfer event + PUSH 0 + LOG3 + !Burnable
			if a.hasTransferEvent && a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0 {
				if !a.detected["Burnable"] {
					a.addFlag("ZeroAddressTransfer", 10)
				}
			}
		}
		a.lastOp = op
		a.pc++
	}

	if !a.hasSstore {
		a.addFlag("Stateless", 30)

		// FakeToken: Stateless but has token signatures
		isTokenLike := a.hasTransferSig
		if !isTokenLike {
			for _, f := range a.flags {
				if f == "Mintable" || f == "Burnable" {
					isTokenLike = true
					break
				}
			}
		}
		if isTokenLike {
			a.addFlag("FakeToken", 50)
		}
	}

	if a.hasTransferSig && a.hasDiv {
		a.addFlag("TaxToken", 20)
	}
	if a.hasStrictBalance {
		a.addFlag("StrictBalanceEquality", 10)
	}
	if a.hasUncheckedCall {
		a.addFlag("UncheckedLowLevelCall", 15)
		a.addFlag("UncheckedReturn", 15)
		a.addFlag("UncheckedCall", 15)
	}
	if !a.canSendEth {
		a.addFlag("LockedEther", 5)
	}
	if a.hasDivBeforeMul {
		a.addFlag("DivideBeforeMultiply", 10)
	}
	if a.hasShadowing {
		a.addFlag("ShadowingState", 5)
	}
	if a.hasTransferSig && !a.hasTransferEvent {
		a.addFlag("NoTransferEvent", 20)
		if a.hasSstore {
			a.addFlag("PotentialHoneypot", 50)
		}
	}
	if a.hasTransferSig && !a.isMintable && a.hasSstore && a.hasCaller && a.hasAddSubMul {
		a.addFlag("HiddenMint", 40)
	}

	if a.hasRevert && !a.hasReturn && !a.hasStop && !a.hasSelfDestruct {
		a.addFlag("ReturnBomb", 50)
	}
	if a.hasERC1820 {
		a.addFlag("ERC777Reentrancy", 20)
	}
	if a.hasLowLevelCall && !a.hasReturnDataSize {
		a.addFlag("UncheckedReturnData", 10)
	}
	if a.hasInfiniteLoop {
		a.addFlag("InfiniteLoop", 20)
		a.addFlag("GasGriefingLoop", 30)
	}
	if a.hasCallInLoop {
		a.addFlag("CallInLoop", 10)
	}
	if a.hasDelegateCallInLoop {
		a.addFlag("DelegateCallInLoop", 20)
	}
	if a.hasFactoryInLoop {
		a.addFlag("FactoryInLoop", 15)
	}
	if a.hasSelfDestructInLoop {
		a.addFlag("SelfDestructInLoop", 50)
	}
	if a.hasGasDependentLoop {
		a.addFlag("GasDependentLoop", 10)
		a.addFlag("GasGriefing", 30)
		a.addFlag("GasGriefingLoop", 30)
	}
	if a.hasInvalid {
		a.addFlag("GasGriefing", 30)
	}
	if a.countSstore > 0 && a.countSload == 0 {
		a.addFlag("SuspiciousStateChange", 10)
	}
	if a.hasSstoreInLoop {
		a.addFlag("CostlyLoop", 10)
	}
	if a.hasDelegateCall && a.hasSelfDestruct {
		a.addFlag("ProxyDestruction", 20)
	}
	if a.hasCreate2 && a.hasSelfDestruct {
		a.addFlag("MetamorphicExploit", 20)
	}
	if a.hasAddSubMul && !a.hasPanic {
		a.addFlag("UncheckedMath", 10)
	}
	if a.hasDelegateCall && a.hasCalldataLoad {
		a.addFlag("UnsafeDelegateCall", 20)
	}
	if a.hasDelegateCall && !a.hasHardcodedDelegate {
		a.addFlag("UnrestrictedDelegateCall", 30)
	}
	if a.hasReentrancyGuard {
		a.addFlag("ReentrancyGuard", 0)
	}
	if a.hasDynamicJump && a.hasCalldataLoad {
		a.addFlag("ArbitraryJump", 40)
	}
	if a.hasAnd && a.hasCalldataLoad {
		a.addFlag("IntegerTruncation", 10)
	}
	if a.hasTransferSig && a.hasTimestamp {
		a.addFlag("TradingCooldown", 10)
	}
	if a.hasTransferSig && a.hasCaller {
		a.addFlag("OwnerTransferCheck", 5)
	}
	if a.hasTransferEvent && !a.hasSstore {
		a.addFlag("FakeTransferEvent", 50)
	}
	if a.hasSelfDestruct && a.hasCaller {
		a.addFlag("PrivilegedSelfDestruct", 20)
	}
	if a.hasSelfDestruct && !a.hasCaller && !a.hasOrigin {
		a.addFlag("UnprotectedSelfDestruct", 50)
	}
	if a.hasLoop && a.hasGasLimit {
		a.addFlag("DoSGasLimit", 15)
	}
	if a.hasDynamicCall && a.hasCalldataLoad {
		a.addFlag("TokenDraining", 30)
	}
	if a.hasEcrecover && !a.hasSValueCheck {
		a.addFlag("SignatureMalleability", 20)
	}
	if a.hasKeccak256 && a.hasEq && a.countSload > 0 {
		a.addFlag("FrontRunning", 30)
	}
	if a.hasSelfDestruct && (a.hasCreate || a.hasCreate2) {
		a.addFlag("GasTokenMinting", 40)
	}
	if a.hasWriteToSlotZero {
		a.addFlag("UninitializedPointer", 20)
	}
	if a.hasTransferSig && !a.hasIsZero && !a.hasEq {
		a.addFlag("MissingZeroCheck", 10)
	}
	if a.hasTransferEvent && a.countLogs == 0 {
		a.addFlag("UnusedEvent", 10)
	}
	if a.hasEcrecover && a.countSload == 0 {
		a.addFlag("SignatureReplay", 20)
	}
	if a.hasCaller && a.hasSstore && a.countSload == 0 {
		a.addFlag("UninitializedConstructor", 30)
	}
	if a.hasTransferEvent && !a.hasTransferSig {
		a.addFlag("MisleadingFunctionName", 20)
	}
	if a.hasBalanceOf && !a.hasSstore {
		a.addFlag("FakeHighBalance", 40)
	}
	if a.hasTransferSig && a.hasSubConstant {
		a.addFlag("HiddenFee", 20)
	}

	hasBurnable := false
	hasUpgradable := false
	hasOwnable := false
	hasWithdrawal := false
	for _, f := range a.flags {
		if f == "Burnable" {
			hasBurnable = true
		}
		if f == "Upgradable" {
			hasUpgradable = true
		}
		if f == "Ownable" {
			hasOwnable = true
		}
		if f == "Withdrawal" {
			hasWithdrawal = true
		}
	}
	if hasBurnable && !hasOwnable {
		a.addFlag("PublicBurn", 30)
	}
	if hasUpgradable && !hasOwnable {
		a.addFlag("UnprotectedUpgrade", 40)
	}
	if hasWithdrawal && !a.canSendEth {
		a.addFlag("PhantomFunction", 40)
	}
	if hasWithdrawal && (a.hasRevert || a.hasInvalid || a.hasDelegateCall) {
		a.addFlag("StrawManContract", 50)
	}
	if hasWithdrawal && a.canSendEth && a.countSload == 0 {
		a.addFlag("UnprotectedEtherWithdrawal", 40)
	}
	if a.hasGasBeforeCall && !a.hasReentrancyGuard {
		a.addFlag("ReentrancyNoGasLimit", 30)
	}
	if a.hasDelegateCall && !a.hasEIP1967 {
		a.addFlag("NonStandardProxy", 20)
	}
	if a.hasDelegateCall && len(a.detected) > 0 {
		// If we detected other flags (implying selectors/features) and have delegatecall, potential clash
		// This is a heuristic approximation
		a.addFlag("ProxySelectorClash", 15)
	}
	if a.hasDelegateCallToSelf {
		a.addFlag("DelegateCallToSelf", 30)
	}
	// MaliciousProxy is covered by HardcodedBlacklistedAddress logic if the address is known

	return a.flags, a.score
}

func bytesToInt(b []byte) int {
	res := 0
	for _, v := range b {
		res = (res << 8) | int(v)
	}
	return res
}
