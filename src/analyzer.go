package main

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

var (
	tornadoRouter      = common.HexToAddress("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b").Bytes()
	transferSig        = [4]byte{0xa9, 0x05, 0x9c, 0xbb}
	balanceOfSig       = [4]byte{0x70, 0xa0, 0x82, 0x31}
	transferFromSig    = [4]byte{0x23, 0xb8, 0x72, 0xdd}
	fakeReturnSig      = []byte{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
	transferEventTopic = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").Bytes()
	erc1820Addr        = common.HexToAddress("0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24").Bytes()
	eip1967Impl        = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").Bytes()
	eip1967Admin       = common.HexToHash("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103").Bytes()
	eip1822Slot        = common.HexToHash("0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7").Bytes()
	eip1167Prefix      = []byte{0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73}

	selectors = map[[4]byte]struct {
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
		{0x09, 0x5e, 0xa7, 0xb3}: {"ApprovalFunction", 0},
		{0x10, 0xd1, 0xe8, 0x5c}: {"FlashLoanReceiver", 10},
		{0x23, 0xe3, 0x0c, 0x8b}: {"FlashLoanReceiver", 10},
	}
)

type loopSnapshot struct {
	calls, delegateCalls, creates, selfDestructs, gasOps, sstores int
}

type Analyzer struct {
	code []byte
	pc   int

	flags    []string
	score    int
	detected map[string]bool

	lastOp           byte
	lastPushData     []byte
	lastDivPC        int
	lastTimestampPC  int
	lastOriginPC     int
	lastStaticCallPC int
	jumpDests        map[int]loopSnapshot

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
	heuristicScores    map[string]int
}

func NewAnalyzer(code []byte) *Analyzer {
	return &Analyzer{
		code:             code,
		detected:         make(map[string]bool),
		jumpDests:        make(map[int]loopSnapshot),
		flags:            make([]string, 0, 50), // Pre-allocate for typical flag count
		lastDivPC:        -1,
		lastTimestampPC:  -1,
		lastStaticCallPC: -1,
		lastOriginPC:     -1,
		writtenSlots:     make(map[int]bool),
		readSlots:        make(map[int]bool),
		heuristicScores:  make(map[string]int),
	}
}

func (a *Analyzer) Reset(code []byte) {
	a.code = code
	a.pc = 0
	a.flags = a.flags[:0]
	clear(a.detected)
	clear(a.jumpDests)
	a.lastOp = 0
	a.lastPushData = nil
	a.lastDivPC = -1
	a.lastTimestampPC = -1
	a.lastOriginPC = -1
	a.lastStaticCallPC = -1
	a.countCalls = 0
	a.countDelegateCalls = 0
	a.countCreates = 0
	a.countSelfDestructs = 0
	a.countGasOps = 0
	a.countSload = 0
	a.countSstore = 0
	a.countLogs = 0
	clear(a.writtenSlots)
	clear(a.readSlots)
}

func (a *Analyzer) UpdateHeuristics(enabled, disabled map[string]bool, heuristicScores map[string]int) {
	a.enabledHeuristics = enabled
	a.disabledHeuristics = disabled
	a.heuristicScores = heuristicScores
}

func (a *Analyzer) addFlag(flag string) {
	if a.detected[flag] {
		return
	}
	// Check disabled first
	if len(a.disabledHeuristics) > 0 && a.disabledHeuristics[flag] {
		return
	}
	// Check enabled if present (allowlist mode)
	if len(a.enabledHeuristics) > 0 && !a.enabledHeuristics[flag] {
		return
	}
	a.detected[flag] = true
	a.flags = append(a.flags, flag)
	a.score += a.heuristicScores[flag]
}

func (a *Analyzer) Analyze() ([]string, int) {
	var (
		lastSelector             [4]byte
		lastSelectorPC           = -1
		hasSelfDestruct          = false
		hasDelegateCall          = false
		hasTimestamp             = false
		hasCaller                = false
		hasAddress               = false
		hasOrigin                = false
		hasSstore                = false
		hasGasPrice              = false
		hasExtCodeSize           = false
		hasExtCodeHash           = false
		hasCoinbase              = false
		hasDifficulty            = false
		hasGasLimit              = false
		hasChainID               = false
		hasSelfBalance           = false
		hasCreate2               = false
		hasBlockNumber           = false
		hasBlockHash             = false
		hasCalldataSize          = false
		hasCreate                = false
		hasLowLevelCall          = false
		hasDiv                   = false
		hasStrictBalance         = false
		hasUncheckedCall         = false
		canSendEth               = false
		hasGas                   = false
		hasDivBeforeMul          = false
		hasShadowing             = false
		hasCodeSize              = false
		hasWriteToSlotZero       = false
		hasHardcodedGas          = false
		hasRevert                = false
		hasReturn                = false
		hasStop                  = false
		hasReturnDataSize        = false
		hasLoop                  = false
		hasInfiniteLoop          = false
		hasCallInLoop            = false
		hasDelegateCallInLoop    = false
		hasFactoryInLoop         = false
		hasSelfDestructInLoop    = false
		hasGasDependentLoop      = false
		hasSstoreInLoop          = false
		hasDelegateCallToZero    = false
		hasHardcodedSelfDestruct = false
		hasDelegateCallToSelf    = false
		hasHardcodedDelegate     = false
		hasInvalid               = false
		hasGasBeforeCall         = false

		hasAddSubMul       = false
		hasSubConstant     = false
		hasCalldataLoad    = false
		hasPanic           = false
		hasReentrancyGuard = false
		hasBitwiseShift    = false
		hasAnd             = false
		isUnreachable      = false
		hasDeadCode        = false
		hasDynamicJump     = false
		hasDynamicCall     = false
		hasKeccak256       = false
		hasEq              = false
		hasIsZero          = false
		hasEcrecover       = false
		hasSValueCheck     = false

		// Special signatures
		hasTransferSig   = false
		hasBalanceOf     = false
		isMintable       = false
		hasTransferEvent = false
		hasERC1820       = false
		hasEIP1967       = false
		hasEIP1822       = false
		hasEIP1167       = false
	)

	if bytes.HasPrefix(a.code, eip1167Prefix) {
		hasEIP1167 = true
		a.addFlag("MinimalProxy")
	}

	for a.pc < len(a.code) {
		op := a.code[a.pc]

		// Check for Fake Return Pattern (PUSH1 01 ... RETURN)
		// 600160005260206000f3
		if op == 0x60 && bytes.HasPrefix(a.code[a.pc:], fakeReturnSig) {
			a.addFlag("FakeReturn")
		}

		// DeadCode check: Code after terminator that isn't JUMPDEST is unreachable
		if isUnreachable && op != 0x5B {
			if !hasDeadCode {
				hasDeadCode = true
				a.addFlag("DeadCode")
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
						hasTransferSig = true
					} else if sig == balanceOfSig {
						hasBalanceOf = true
					} else if sel, ok := selectors[sig]; ok {
						a.addFlag(sel.flag)
						if sel.flag == "Mintable" {
							isMintable = true
						}
					}

					// Check Panic signature (0x4e487b71)
					if sig == [4]byte{0x4e, 0x48, 0x7b, 0x71} {
						hasPanic = true
					}
				}

				// Check for specific addresses and topics
				if op == 0x73 { // PUSH20
					if bytes.Equal(a.lastPushData, tornadoRouter) {
						a.addFlag("HardcodedBlacklistedAddress")
					} else if bytes.Equal(a.lastPushData, erc1820Addr) {
						hasERC1820 = true
					}
				}
				if op == 0x7F { // PUSH32
					if bytes.Equal(a.lastPushData, transferEventTopic) {
						hasTransferEvent = true
					}
					if bytes.Equal(a.lastPushData, eip1967Impl) || bytes.Equal(a.lastPushData, eip1967Admin) {
						hasEIP1967 = true
					}
					if bytes.Equal(a.lastPushData, eip1822Slot) {
						hasEIP1822 = true
					}
				}

				// Check for ReentrancyGuard string
				if bytes.Contains(a.lastPushData, []byte("ReentrancyGuard")) {
					hasReentrancyGuard = true
				}

				// Check for S-value constant (approximate check for half-curve order)
				if len(a.lastPushData) == 32 && a.lastPushData[0] == 0x7f && a.lastPushData[1] == 0xff {
					hasSValueCheck = true
				}
			} else {
				a.lastPushData = nil
			}
			a.lastOp = op
			a.pc += pushBytes + 1
			continue
		}

		if op == 0x5B { // JUMPDEST
			isUnreachable = false
		}

		switch op {
		case 0x01, 0x03: // ADD, SUB
			hasAddSubMul = true
			if op == 0x03 && a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				hasSubConstant = true
			}
		case 0x1B, 0x1C, 0x1D: // SHL, SHR, SAR
			if !hasBitwiseShift {
				hasBitwiseShift = true
				a.addFlag("BitwiseLogic")
			}
		case 0x16: // AND
			hasAnd = true
		case 0x35: // CALLDATALOAD
			hasCalldataLoad = true
		case 0x5B: // JUMPDEST
			a.jumpDests[a.pc] = loopSnapshot{
				a.countCalls, a.countDelegateCalls, a.countCreates, a.countSelfDestructs, a.countGasOps, a.countSstore,
			}
		case 0x56, 0x57: // JUMP, JUMPI
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F { // Previous op was PUSH
				dest := bytesToInt(a.lastPushData)
				if snap, exists := a.jumpDests[dest]; exists {
					// Backward jump detected -> Loop
					if !hasLoop {
						hasLoop = true
						a.addFlag("LoopDetected")
					}
					if op == 0x56 { // Unconditional backward jump
						hasInfiniteLoop = true
					}
					// Check what happened inside the loop
					if a.countCalls > snap.calls {
						hasCallInLoop = true
					}
					if a.countDelegateCalls > snap.delegateCalls {
						hasDelegateCallInLoop = true
					}
					if a.countCreates > snap.creates {
						hasFactoryInLoop = true
					}
					if a.countSelfDestructs > snap.selfDestructs {
						hasSelfDestructInLoop = true
					}
					if a.countGasOps > snap.gasOps {
						hasGasDependentLoop = true
					}
					if a.countSstore > snap.sstores {
						hasSstoreInLoop = true
					}
				}
			} else {
				hasDynamicJump = true
			}
		case 0x38: // CODESIZE
			if !hasCodeSize {
				hasCodeSize = true
				a.addFlag("SuspiciousCodeSize")
			}
		case 0x3D: // RETURNDATASIZE
			hasReturnDataSize = true
		case 0x20: // SHA3 / KECCAK256
			hasKeccak256 = true
		case 0x10, 0x11, 0x12, 0x13, 0x14: // LT, GT, SLT, SGT, EQ
			if op == 0x14 {
				hasEq = true
			}
			if a.lastTimestampPC != -1 && a.pc-a.lastTimestampPC < 15 {
				a.addFlag("BlockTimestampManipulation")
			}
		case 0x15: // ISZERO
			hasIsZero = true
		case 0x04: // DIV
			hasDiv = true
			a.lastDivPC = a.pc
		case 0x02: // MUL
			hasAddSubMul = true
			if a.lastDivPC != -1 && a.pc-a.lastDivPC < 12 {
				hasDivBeforeMul = true
			}
		case 0x31: // BALANCE
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x14 { // EQ
				hasStrictBalance = true
			}
		case 0x54: // SLOAD
			a.countSload++
			if a.lastStaticCallPC != -1 && a.pc-a.lastStaticCallPC < 10 {
				a.addFlag("ReadOnlyReentrancy")
			}
			if a.lastOp == 0x5F || (a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0) {
				a.addFlag("UninitializedLocalVariables")
			}
			// Track read slots (simplified: only tracks constant slots pushed immediately before)
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				slot := bytesToInt(a.lastPushData)
				a.readSlots[slot] = true
				if !a.writtenSlots[slot] {
					a.addFlag("UninitializedState")
				}
			}
		case 0x51, 0x52, 0x53: // MLOAD, MSTORE, MSTORE8
			if a.lastOp == 0x54 { // SLOAD
				a.addFlag("AssemblyErrorProne")
			}
		case 0x59: // MSIZE
			a.addFlag("AssemblyErrorProne")
		case 0x50: // POP
			if a.lastOp == 0x54 { // SLOAD
				hasShadowing = true
				a.addFlag("ShadowingState")
			}
		case 0x5A: // GAS
			a.countGasOps++
			if !hasGas {
				hasGas = true
				a.addFlag("GasUsage")
			}
		case 0xFF: // SELFDESTRUCT
			a.countSelfDestructs++
			if !hasSelfDestruct {
				hasSelfDestruct = true
				a.addFlag("SelfDestruct")
			}
			if a.lastOp == 0x73 && !hasHardcodedSelfDestruct { // PUSH20 before SELFDESTRUCT
				hasHardcodedSelfDestruct = true
				a.addFlag("HardcodedSelfDestruct")
			}
			canSendEth = true
		case 0xF4: // DELEGATECALL
			a.countDelegateCalls++
			if !hasDelegateCall {
				hasDelegateCall = true
				a.addFlag("DelegateCall")
			}
			if a.lastOp == 0x73 { // PUSH20
				a.addFlag("SuspiciousDelegate")
				hasHardcodedDelegate = true
			}
			if hasAddress { // Was ADDRESS before DELEGATECALL
				hasDelegateCallToSelf = true
			}
			// Check for DelegateCall to Zero (PUSH0 or PUSH1 0x00 before DELEGATECALL)
			if a.lastOp == 0x5F || (a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0) {
				if !hasDelegateCallToZero {
					hasDelegateCallToZero = true
					a.addFlag("DelegateCallToZero")
				}
			}
			// Check for Unchecked Return (DELEGATECALL + POP or STOP)
			if a.pc+1 < len(a.code) && (a.code[a.pc+1] == 0x50 || a.code[a.pc+1] == 0x00) {
				hasUncheckedCall = true
				a.addFlag("UncheckedDelegateCall")
			}
			canSendEth = true
		case 0x42: // TIMESTAMP
			if !hasTimestamp {
				hasTimestamp = true
				a.addFlag("TimestampDependence")
			}
			a.lastTimestampPC = a.pc
		case 0x33: // CALLER (msg.sender)
			hasCaller = true
		case 0x30: // ADDRESS
			hasAddress = true
		case 0x32: // ORIGIN
			if !hasOrigin {
				hasOrigin = true
				a.addFlag("TxOrigin")
			}
			a.lastOriginPC = a.pc
		case 0x55: // SSTORE
			hasSstore = true
			a.countSstore++
			if a.lastOp == 0x35 { // CALLDATALOAD
				a.addFlag("ArbitraryStorageWrite")
			}
			if a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0 {
				if !hasWriteToSlotZero {
					hasWriteToSlotZero = true
					a.addFlag("WriteToSlotZero")
				}
			}
			// Track written slots
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				slot := bytesToInt(a.lastPushData)
				a.writtenSlots[slot] = true
			}
		case 0x3A: // GASPRICE
			if !hasGasPrice {
				hasGasPrice = true
				a.addFlag("GasPriceCheck")
			}
		case 0x3B: // EXTCODESIZE
			if !hasExtCodeSize {
				hasExtCodeSize = true
				a.addFlag("AntiContractCheck")
			}
		case 0x3F: // EXTCODEHASH
			if !hasExtCodeHash {
				hasExtCodeHash = true
				a.addFlag("CodeHashCheck")
			}
		case 0x41: // COINBASE
			if !hasCoinbase {
				hasCoinbase = true
				a.addFlag("CoinbaseCheck")
			}
		case 0x43: // NUMBER
			if !hasBlockNumber {
				hasBlockNumber = true
				a.addFlag("BlockNumberCheck")
			}
		case 0x44: // DIFFICULTY (PREVRANDAO)
			if !hasDifficulty {
				hasDifficulty = true
				a.addFlag("WeakRandomness")
			}
		case 0x45: // GASLIMIT
			if !hasGasLimit {
				hasGasLimit = true
				a.addFlag("BlockStuffing")
			}
		case 0x46: // CHAINID
			if !hasChainID {
				hasChainID = true
				a.addFlag("ChainIDCheck")
			}
		case 0x47: // SELFBALANCE
			if !hasSelfBalance {
				hasSelfBalance = true
				a.addFlag("CheckOwnBalance")
			}
		case 0xF5: // CREATE2
			if !hasCreate2 {
				hasCreate2 = true
				a.addFlag("Metamorphic")
			}
			a.countCreates++
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x50 {
				a.addFlag("UncheckedCreate")
			}
			canSendEth = true
		case 0x40: // BLOCKHASH
			if !hasBlockHash {
				hasBlockHash = true
				a.addFlag("BadRandomness")
			}
		case 0x36: // CALLDATASIZE
			if !hasCalldataSize {
				hasCalldataSize = true
				a.addFlag("CalldataSizeCheck")
			}
		case 0xF0: // CREATE
			a.countCreates++
			if !hasCreate {
				hasCreate = true
				a.addFlag("ContractFactory")
			}
			if a.pc+1 < len(a.code) && a.code[a.pc+1] == 0x50 {
				a.addFlag("UncheckedCreate")
			}
			canSendEth = true
		case 0xFA: // STATICCALL
			a.lastStaticCallPC = a.pc
			if a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 1 {
				hasEcrecover = true
				a.addFlag("UncheckedEcrecover")
			}
			// Check for Unchecked Return (STATICCALL + POP or STOP)
			if a.pc+1 < len(a.code) && (a.code[a.pc+1] == 0x50 || a.code[a.pc+1] == 0x00) {
				hasUncheckedCall = true
			}
			canSendEth = true
		case 0xF1, 0xF2: // CALL, CALLCODE
			a.countCalls++
			if a.pc+1 < len(a.code) && (a.code[a.pc+1] == 0x50 || a.code[a.pc+1] == 0x00) { // CALL/CALLCODE + POP or STOP
				hasUncheckedCall = true
				if op == 0xF1 && a.lastOp >= 0x60 && a.lastOp <= 0x7F {
					if a.lastOp == 0x61 && bytes.Equal(a.lastPushData, []byte{0x08, 0xfc}) {
						a.addFlag("UncheckedSend")
					} else {
						a.addFlag("UncheckedLowLevelCall")
					}
				}
				if lastSelectorPC != -1 && a.pc-lastSelectorPC < 30 {
					switch lastSelector {
					case transferSig:
						a.addFlag("UncheckedTransfer")
					case transferFromSig:
						a.addFlag("UncheckedTransferFrom")
					}
				}
			}
			if a.lastOriginPC != -1 && a.pc-a.lastOriginPC < 20 {
				a.addFlag("TxOriginPhishing")
			}
			if op == 0xF1 && a.lastOp == 0x5A { // GAS + CALL
				hasGasBeforeCall = true
			}
			// Check for Hardcoded Gas Limit (PUSH + CALL)
			if a.lastOp >= 0x60 && a.lastOp <= 0x7F {
				if !hasHardcodedGas {
					hasHardcodedGas = true
					a.addFlag("HardcodedGasLimit")
				}
			}
			if !hasLowLevelCall {
				hasLowLevelCall = true
				a.addFlag("LowLevelCall")
			}
			if a.lastOp < 0x60 || a.lastOp > 0x7F {
				hasDynamicCall = true
			}
			canSendEth = true
		case 0xFD: // REVERT
			hasRevert = true
			isUnreachable = true
		case 0xF3: // RETURN
			hasReturn = true
			isUnreachable = true
		case 0xFE: // INVALID
			hasInvalid = true
			isUnreachable = true
		case 0x00: // STOP
			hasStop = true
			isUnreachable = true
		case 0xA0, 0xA1, 0xA2, 0xA3, 0xA4: // LOG0 - LOG4
			a.countLogs++
			// Heuristic for ZeroAddressTransfer: Transfer event + PUSH 0 + LOG3 + !Burnable
			if hasTransferEvent && a.lastOp == 0x60 && len(a.lastPushData) == 1 && a.lastPushData[0] == 0 {
				if !a.detected["Burnable"] {
					a.addFlag("ZeroAddressTransfer")
				}
			}
		}
		a.lastOp = op
		a.pc++
	}

	if !hasSstore {
		a.addFlag("Stateless")
		// FakeToken: Stateless but has token signatures
		isTokenLike := hasTransferSig
		if !isTokenLike {
			// Check if any selector-based token flags were added
			for _, f := range a.flags {
				if f == "Mintable" || f == "Burnable" {
					isTokenLike = true
					break
				}
			}
		}
		if isTokenLike {
			a.addFlag("FakeToken")
		}
	}

	if hasTransferSig && hasDiv {
		a.addFlag("TaxToken")
	}
	if hasStrictBalance {
		a.addFlag("StrictBalanceEquality")
	}
	if hasUncheckedCall {
		a.addFlag("UncheckedCall")
	}
	if !canSendEth {
		a.addFlag("LockedEther")
	}
	if hasDivBeforeMul {
		a.addFlag("DivideBeforeMultiply")
	}
	if hasShadowing {
		a.addFlag("ShadowingState")
	}
	if hasTransferSig && !hasTransferEvent {
		a.addFlag("NoTransferEvent")
		if hasSstore {
			a.addFlag("PotentialHoneypot")
		}
	}
	if hasTransferSig && !isMintable && hasSstore && hasCaller && hasAddSubMul {
		a.addFlag("HiddenMint")
	}
	if hasTransferSig && hasSstore && hasLoop {
		a.addFlag("BurstMint")
	}
	if hasCaller && hasSstore && a.countSload == 0 {
		a.addFlag("SelfAllocation")
		a.addFlag("UninitializedConstructor")
	}

	if hasRevert && !hasReturn && !hasStop && !hasSelfDestruct {
		a.addFlag("ReturnBomb")
	}
	if hasERC1820 {
		a.addFlag("ERC777Reentrancy")
	}
	if hasLowLevelCall && !hasReturnDataSize {
		a.addFlag("UncheckedReturnData")
	}
	if hasInfiniteLoop {
		a.addFlag("InfiniteLoop")
		a.addFlag("GasGriefingLoop")
	}
	if hasCallInLoop {
		a.addFlag("CallInLoop")
	}
	if hasDelegateCallInLoop {
		a.addFlag("DelegateCallInLoop")
	}
	if hasFactoryInLoop {
		a.addFlag("FactoryInLoop")
	}
	if hasSelfDestructInLoop {
		a.addFlag("SelfDestructInLoop")
	}
	if hasGasDependentLoop {
		a.addFlag("GasDependentLoop")
		a.addFlag("GasGriefing")
		a.addFlag("GasGriefingLoop")
	}
	if hasInvalid {
		a.addFlag("GasGriefing")
	}
	if a.countSstore > 0 && a.countSload == 0 {
		a.addFlag("SuspiciousStateChange")
	}
	if hasSstoreInLoop {
		a.addFlag("CostlyLoop")
	}
	if hasDelegateCall && hasSelfDestruct {
		a.addFlag("ProxyDestruction")
	}
	if hasCreate2 && hasSelfDestruct {
		a.addFlag("MetamorphicExploit")
	}
	if hasAddSubMul && !hasPanic {
		a.addFlag("UncheckedMath")
	}
	if hasDelegateCall && hasCalldataLoad {
		a.addFlag("UnsafeDelegateCall")
	}
	if hasDelegateCall && !hasHardcodedDelegate {
		a.addFlag("UnrestrictedDelegateCall")
	}
	if hasReentrancyGuard {
		a.addFlag("ReentrancyGuard")
	}
	if hasDynamicJump && hasCalldataLoad {
		a.addFlag("ArbitraryJump")
	}
	if hasAnd && hasCalldataLoad {
		a.addFlag("IntegerTruncation")
	}
	if hasTransferSig && hasTimestamp {
		a.addFlag("TradingCooldown")
	}
	if hasTransferSig && hasCaller {
		a.addFlag("OwnerTransferCheck")
	}
	if hasTransferEvent && !hasSstore {
		a.addFlag("FakeTransferEvent")
	}
	if hasSelfDestruct && hasCaller {
		a.addFlag("PrivilegedSelfDestruct")
	}
	if hasSelfDestruct && ((!hasCaller && !hasOrigin) || (!hasEq && !hasIsZero)) {
		a.addFlag("UnprotectedSelfDestruct")
	}
	if hasLoop && hasGasLimit {
		a.addFlag("DoSGasLimit")
	}
	if hasDynamicCall && hasCalldataLoad {
		a.addFlag("TokenDraining")
	}
	if hasEcrecover && !hasSValueCheck {
		a.addFlag("SignatureMalleability")
	}
	if hasKeccak256 && hasEq && a.countSload > 0 {
		a.addFlag("FrontRunning")
	}
	if hasSelfDestruct && (hasCreate || hasCreate2) {
		a.addFlag("GasTokenMinting")
	}
	if hasWriteToSlotZero {
		a.addFlag("UninitializedPointer")
	}
	if hasTransferSig && !hasIsZero && !hasEq {
		a.addFlag("MissingZeroCheck")
	}
	if hasTransferEvent && a.countLogs == 0 {
		a.addFlag("TransferTopicWithoutLogs")
	}
	if hasEcrecover && a.countSload == 0 {
		a.addFlag("SignatureReplay")
	}
	if hasTransferEvent && !hasTransferSig {
		a.addFlag("MisleadingFunctionName")
	}
	if hasBalanceOf && !hasSstore {
		a.addFlag("FakeHighBalance")
	}
	if hasTransferSig && hasSubConstant {
		a.addFlag("HiddenFee")
	}
	if a.detected["ApprovalFunction"] && !hasTransferSig {
		a.addFlag("HiddenApproval")
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
		a.addFlag("PublicBurn")
	}
	if hasUpgradable && !hasOwnable {
		a.addFlag("UnprotectedUpgrade")
	}
	if hasSelfDestruct && !hasOwnable {
		a.addFlag("SelfDestructNoOwner")
	}
	if hasWithdrawal && !canSendEth {
		a.addFlag("PhantomFunction")
	}
	if hasWithdrawal && (hasRevert || hasInvalid || hasDelegateCall) {
		a.addFlag("StrawManContract")
	}
	if hasWithdrawal && canSendEth && a.countSload == 0 {
		a.addFlag("UnprotectedEtherWithdrawal")
	}
	if hasGasBeforeCall && !hasReentrancyGuard {
		a.addFlag("ReentrancyNoGasLimit")
	}
	if hasDelegateCall && !hasEIP1967 && !hasEIP1822 && !hasEIP1167 {
		a.addFlag("NonStandardProxy")
	}
	if hasDelegateCall && len(a.detected) > 1 {
		// Only trigger clash if we have high-risk selectors
		hasHighRiskSelector := hasTransferSig || isMintable
		if hasHighRiskSelector {
			a.addFlag("ProxySelectorClash")
		}
	}
	if hasDelegateCallToSelf {
		a.addFlag("DelegateCallToSelf")
	}
	if (hasTransferSig || hasBalanceOf) && !hasReturn {
		a.addFlag("MissingReturn")
	}
	// MaliciousProxy is covered by HardcodedBlacklistedAddress logic if the address is known

	return a.flags, a.score
}

func bytesToInt(b []byte) int {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	res := 0
	for _, v := range b {
		res = (res << 8) | int(v)
	}
	return res
}
