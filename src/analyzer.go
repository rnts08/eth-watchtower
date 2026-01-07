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

	lastOp       byte
	lastPushData []byte
	lastDivPC    int
	jumpDests    map[int]loopSnapshot

	// Opcode scanning flags
	hasSelfDestruct          bool
	hasDelegateCall          bool
	hasTimestamp             bool
	hasCaller                bool
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
	hasHardcodedBlacklist    bool
	hasHardcodedDelegate     bool
	hasInvalid               bool

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
}

func NewAnalyzer(code []byte) *Analyzer {
	return &Analyzer{
		code:      code,
		detected:  make(map[string]bool),
		jumpDests: make(map[int]loopSnapshot),
		lastDivPC: -1,
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

	*a = Analyzer{}

	a.code = code
	a.flags = flags
	a.detected = detected
	a.jumpDests = jumpDests
	a.lastDivPC = -1
}

func (a *Analyzer) addFlag(flag string, s int) {
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
	hasTransferSig := false
	hasBalanceOf := false
	isMintable := false

	// Fake Return Pattern: PUSH1 01 PUSH1 00 MSTORE PUSH1 20 PUSH1 00 RETURN
	// 600160005260206000f3
	fakeReturnSig := []byte{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}

	// Opcode scanning
	hasSelfDestruct := false
	hasDelegateCall := false
	hasTimestamp := false
	hasCaller := false
	hasOrigin := false
	hasSstore := false
	hasGasPrice := false
	hasExtCodeSize := false
	hasExtCodeHash := false
	hasCoinbase := false
	hasDifficulty := false
	hasGasLimit := false
	hasChainID := false
	hasSelfBalance := false
	hasCreate2 := false
	hasBlockNumber := false
	hasBlockHash := false
	hasCalldataSize := false
	hasCreate := false
	hasLowLevelCall := false
	hasDiv := false
	hasStrictBalance := false
	hasUncheckedCall := false
	canSendEth := false
	hasGas := false
	hasDivBeforeMul := false
	hasShadowing := false
	hasCodeSize := false
	hasWriteToSlotZero := false
	hasHardcodedGas := false
	hasRevert := false
	hasReturn := false
	hasStop := false
	hasReturnDataSize := false
	hasLoop := false
	hasInfiniteLoop := false
	hasCallInLoop := false
	hasDelegateCallInLoop := false
	hasFactoryInLoop := false
	hasSelfDestructInLoop := false
	hasGasDependentLoop := false
	hasSstoreInLoop := false
	hasDelegateCallToZero := false
	hasHardcodedSelfDestruct := false
	hasHardcodedBlacklist := false
	hasHardcodedDelegate := false
	hasInvalid := false

	hasAddSubMul := false
	hasSubConstant := false
	hasCalldataLoad := false
	hasPanic := false
	hasReentrancyGuard := false
	hasStaticCall := false
	hasAnd := false
	isUnreachable := false
	hasDeadCode := false
	hasDynamicJump := false
	hasDynamicCall := false
	hasKeccak256 := false
	hasEq := false
	hasIsZero := false
	hasEcrecover := false
	hasSValueCheck := false

	// Counters for loop analysis
	countCalls := 0
	countDelegateCalls := 0
	countCreates := 0
	countSelfDestructs := 0
	countGasOps := 0
	countSload := 0
	countSstore := 0
	jumpDests := make(map[int]struct{ c, dc, cr, sd, g, ss int })

	// Transfer Event Topic
	transferEventTopic := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").Bytes()
	hasTransferEvent := false

	// ERC1820 Registry Address
	erc1820Addr := common.HexToAddress("0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24").Bytes()
	hasERC1820 := false

	// EIP-1967 Storage Slots
	eip1967Impl := common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").Bytes()
	eip1967Admin := common.HexToHash("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103").Bytes()
	hasEIP1967 := false

	pc := 0
	lastOp := byte(0)
	var lastPushData []byte
	lastDivPC := -1

	for pc < len(code) {
		op := code[pc]

		// DeadCode check: Code after terminator that isn't JUMPDEST is unreachable
		if isUnreachable && op != 0x5B {
			if !hasDeadCode {
				hasDeadCode = true
				addFlag("DeadCode", 5)
			}
		}

		// Skip PUSH data (PUSH1=0x60 ... PUSH32=0x7F)
		if op >= 0x60 && op <= 0x7F {
			pushBytes := int(op - 0x5F)
			if pc+1+pushBytes <= len(code) {
				lastPushData = code[pc+1 : pc+1+pushBytes]

				// Check signatures in PUSH data
				if len(lastPushData) >= 4 {
					// Check 4-byte selectors
					// We check the first 4 bytes of the push data
					var sig [4]byte
					copy(sig[:], lastPushData)

					if sig == transferSig {
						hasTransferSig = true
					} else if sig == balanceOfSig {
						hasBalanceOf = true
					} else if val, ok := selectors[sig]; ok {
						addFlag(val.flag, val.score)
						if val.flag == "Mintable" {
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
					if bytes.Equal(lastPushData, tornadoRouter) {
						hasHardcodedBlacklist = true
						addFlag("HardcodedBlacklistedAddress", 50)
					} else if bytes.Equal(lastPushData, erc1820Addr) {
						hasERC1820 = true
					}
					if bytes.Equal(lastPushData, eip1967Impl) || bytes.Equal(lastPushData, eip1967Admin) {
						hasEIP1967 = true
					}
				}
				if op == 0x7F { // PUSH32
					if bytes.Equal(lastPushData, transferEventTopic) {
						hasTransferEvent = true
					}
				}

				// Check for ReentrancyGuard string
				if bytes.Contains(lastPushData, []byte("ReentrancyGuard")) {
					hasReentrancyGuard = true
				}

				// Check for S-value constant (approximate check for half-curve order)
				if len(lastPushData) == 32 && lastPushData[0] == 0x7f && lastPushData[1] == 0xff {
					hasSValueCheck = true
				}
			} else {
				lastPushData = nil
			}
			lastOp = op
			pc += pushBytes + 1
			continue
		}

		if op == 0x5B { // JUMPDEST
			isUnreachable = false
		}

		// Check for Fake Return Pattern (PUSH1 01 ... RETURN)
		// 600160005260206000f3
		if op == 0x60 && bytes.HasPrefix(code[pc:], fakeReturnSig) {
			addFlag("FakeReturn", 20)
		}

		switch op {
		case 0x01, 0x03: // ADD, SUB
			hasAddSubMul = true
			if op == 0x03 && lastOp >= 0x60 && lastOp <= 0x7F {
				hasSubConstant = true
			}
		case 0x16: // AND
			hasAnd = true
		case 0x35: // CALLDATALOAD
			hasCalldataLoad = true
		case 0x5B: // JUMPDEST
			jumpDests[pc] = struct{ c, dc, cr, sd, g, ss int }{
				countCalls, countDelegateCalls, countCreates, countSelfDestructs, countGasOps, countSstore,
			}
		case 0x56, 0x57: // JUMP, JUMPI
			if lastOp >= 0x60 && lastOp <= 0x7F { // Previous op was PUSH
				dest := bytesToInt(lastPushData)
				if snap, exists := jumpDests[dest]; exists {
					// Backward jump detected -> Loop
					if !hasLoop {
						hasLoop = true
						addFlag("LoopDetected", 5)
					}
					if op == 0x56 { // Unconditional backward jump
						hasInfiniteLoop = true
					}
					// Check what happened inside the loop
					if countCalls > snap.c {
						hasCallInLoop = true
					}
					if countDelegateCalls > snap.dc {
						hasDelegateCallInLoop = true
					}
					if countCreates > snap.cr {
						hasFactoryInLoop = true
					}
					if countSelfDestructs > snap.sd {
						hasSelfDestructInLoop = true
					}
					if countGasOps > snap.g {
						hasGasDependentLoop = true
					}
					if countSstore > snap.ss {
						hasSstoreInLoop = true
					}
				}
			} else {
				hasDynamicJump = true
			}
		case 0x38: // CODESIZE
			if !hasCodeSize {
				hasCodeSize = true
				addFlag("SuspiciousCodeSize", 5)
			}
		case 0x3D: // RETURNDATASIZE
			hasReturnDataSize = true
		case 0x20: // SHA3 / KECCAK256
			hasKeccak256 = true
		case 0x14: // EQ
			hasEq = true
		case 0x15: // ISZERO
			hasIsZero = true
		case 0x04: // DIV
			hasDiv = true
			lastDivPC = pc
		case 0x02: // MUL
			hasAddSubMul = true
			if lastDivPC != -1 && pc-lastDivPC < 12 {
				hasDivBeforeMul = true
			}
		case 0x31: // BALANCE
			if pc+1 < len(code) && code[pc+1] == 0x14 { // EQ
				hasStrictBalance = true
			}
		case 0x54: // SLOAD
			countSload++
			if lastOp == 0xFA { // STATICCALL
				addFlag("ReadOnlyReentrancy", 30)
			}
			if lastOp == 0x5F || (lastOp == 0x60 && len(lastPushData) == 1 && lastPushData[0] == 0) {
				addFlag("UninitializedLocalVariables", 20)
			}
		case 0x51, 0x52, 0x53: // MLOAD, MSTORE, MSTORE8
			if lastOp == 0x54 { // SLOAD
				addFlag("AssemblyErrorProne", 20)
			}
		case 0x59: // MSIZE
			addFlag("AssemblyErrorProne", 10)
		case 0x50: // POP
			if lastOp == 0x54 { // SLOAD
				hasShadowing = true
			}
		case 0x5A: // GAS
			countGasOps++
			if !hasGas {
				hasGas = true
				addFlag("GasUsage", 5)
			}
		case 0xFF: // SELFDESTRUCT
			countSelfDestructs++
			if !hasSelfDestruct {
				hasSelfDestruct = true
				addFlag("SelfDestruct", 50)
			}
			if lastOp == 0x73 && !hasHardcodedSelfDestruct { // PUSH20 before SELFDESTRUCT
				hasHardcodedSelfDestruct = true
				addFlag("HardcodedSelfDestruct", 50)
			}
			canSendEth = true
		case 0xF4: // DELEGATECALL
			countDelegateCalls++
			if !hasDelegateCall {
				hasDelegateCall = true
				addFlag("DelegateCall", 20)
			}
			if lastOp == 0x73 { // PUSH20
				addFlag("SuspiciousDelegate", 30)
				hasHardcodedDelegate = true
			}
			// Check for DelegateCall to Zero (PUSH0 or PUSH1 0x00 before DELEGATECALL)
			if lastOp == 0x5F || (lastOp == 0x60 && len(lastPushData) == 1 && lastPushData[0] == 0) {
				if !hasDelegateCallToZero {
					hasDelegateCallToZero = true
					addFlag("DelegateCallToZero", 30)
				}
			}
			canSendEth = true
		case 0x42: // TIMESTAMP
			if !hasTimestamp {
				hasTimestamp = true
				addFlag("TimestampDependence", 5)
			}
		case 0x33: // CALLER (msg.sender)
			hasCaller = true
		case 0x32: // ORIGIN
			if !hasOrigin {
				hasOrigin = true
				addFlag("TxOrigin", 10)
			}
		case 0x55: // SSTORE
			hasSstore = true
			countSstore++
			if lastOp == 0x35 { // CALLDATALOAD
				addFlag("ArbitraryStorageWrite", 30)
			}
			if lastOp == 0x60 && len(lastPushData) == 1 && lastPushData[0] == 0 {
				if !hasWriteToSlotZero {
					hasWriteToSlotZero = true
					addFlag("WriteToSlotZero", 20)
				}
			}
		case 0x3A: // GASPRICE
			if !hasGasPrice {
				hasGasPrice = true
				addFlag("GasPriceCheck", 5)
			}
		case 0x3B: // EXTCODESIZE
			if !hasExtCodeSize {
				hasExtCodeSize = true
				addFlag("AntiContractCheck", 10)
			}
		case 0x3F: // EXTCODEHASH
			if !hasExtCodeHash {
				hasExtCodeHash = true
				addFlag("CodeHashCheck", 10)
			}
		case 0x41: // COINBASE
			if !hasCoinbase {
				hasCoinbase = true
				addFlag("CoinbaseCheck", 5)
			}
		case 0x43: // NUMBER
			if !hasBlockNumber {
				hasBlockNumber = true
				addFlag("BlockNumberCheck", 5)
			}
		case 0x44: // DIFFICULTY (PREVRANDAO)
			if !hasDifficulty {
				hasDifficulty = true
				addFlag("WeakRandomness", 10)
			}
		case 0x45: // GASLIMIT
			if !hasGasLimit {
				hasGasLimit = true
				addFlag("BlockStuffing", 5)
			}
		case 0x46: // CHAINID
			if !hasChainID {
				hasChainID = true
				addFlag("ChainIDCheck", 5)
			}
		case 0x47: // SELFBALANCE
			if !hasSelfBalance {
				hasSelfBalance = true
				addFlag("CheckOwnBalance", 5)
			}
		case 0xF5: // CREATE2
			if !hasCreate2 {
				hasCreate2 = true
				addFlag("Metamorphic", 30)
			}
			countCreates++
			canSendEth = true
		case 0x40: // BLOCKHASH
			if !hasBlockHash {
				hasBlockHash = true
				addFlag("BadRandomness", 15)
			}
		case 0x36: // CALLDATASIZE
			if !hasCalldataSize {
				hasCalldataSize = true
				addFlag("CalldataSizeCheck", 5)
			}
		case 0xF0: // CREATE
			countCreates++
			if !hasCreate {
				hasCreate = true
				addFlag("ContractFactory", 10)
			}
			canSendEth = true
		case 0xFA: // STATICCALL
			hasStaticCall = true
			if lastOp == 0x60 && len(lastPushData) == 1 && lastPushData[0] == 1 {
				hasEcrecover = true
				addFlag("UncheckedEcrecover", 20)
			}
			canSendEth = true
		case 0xF1, 0xF2: // CALL, CALLCODE
			countCalls++
			if op == 0xF1 && pc+1 < len(code) && code[pc+1] == 0x50 { // CALL + POP
				hasUncheckedCall = true
			}
			// Check for Hardcoded Gas Limit (PUSH + CALL)
			if lastOp >= 0x60 && lastOp <= 0x7F {
				if !hasHardcodedGas {
					hasHardcodedGas = true
					addFlag("HardcodedGasLimit", 5)
				}
			}
			if !hasLowLevelCall {
				hasLowLevelCall = true
				addFlag("LowLevelCall", 10)
			}
			if !(lastOp >= 0x60 && lastOp <= 0x7F) {
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
			countLogs++
		}
		lastOp = op
		pc++
	}

	if !hasSstore {
		addFlag("Stateless", 30)

		// FakeToken: Stateless but has token signatures
		isTokenLike := hasTransferSig
		if !isTokenLike {
			for _, f := range flags {
				if f == "Mintable" || f == "Burnable" {
					isTokenLike = true
					break
				}
			}
		}
		if isTokenLike {
			addFlag("FakeToken", 50)
		}
	}

	if hasTransferSig && hasDiv {
		addFlag("TaxToken", 20)
	}
	if hasStrictBalance {
		addFlag("StrictBalanceEquality", 10)
	}
	if hasUncheckedCall {
		addFlag("UncheckedCall", 15)
	}
	if !canSendEth {
		addFlag("LockedEther", 5)
	}
	if hasDivBeforeMul {
		addFlag("DivideBeforeMultiply", 10)
	}
	if hasShadowing {
		addFlag("ShadowingState", 5)
	}
	if hasTransferSig && !hasTransferEvent {
		addFlag("NoTransferEvent", 20)
		if hasSstore {
			addFlag("PotentialHoneypot", 50)
		}
	}
	if hasTransferSig && !isMintable && hasSstore && hasCaller && hasAddSubMul {
		addFlag("HiddenMint", 40)
	}

	if hasRevert && !hasReturn && !hasStop && !hasSelfDestruct {
		addFlag("ReturnBomb", 50)
	}
	if hasERC1820 {
		addFlag("ERC777Reentrancy", 20)
	}
	if hasLowLevelCall && !hasReturnDataSize {
		addFlag("UncheckedReturnData", 10)
	}
	if hasInfiniteLoop {
		addFlag("InfiniteLoop", 20)
		addFlag("GasGriefingLoop", 30)
	}
	if hasCallInLoop {
		addFlag("CallInLoop", 10)
	}
	if hasDelegateCallInLoop {
		addFlag("DelegateCallInLoop", 20)
	}
	if hasFactoryInLoop {
		addFlag("FactoryInLoop", 15)
	}
	if hasSelfDestructInLoop {
		addFlag("SelfDestructInLoop", 50)
	}
	if hasGasDependentLoop {
		addFlag("GasDependentLoop", 10)
		addFlag("GasGriefing", 30)
		addFlag("GasGriefingLoop", 30)
	}
	if hasInvalid {
		addFlag("GasGriefing", 30)
	}
	if countSstore > 0 && countSload == 0 {
		addFlag("SuspiciousStateChange", 10)
	}
	if hasSstoreInLoop {
		addFlag("CostlyLoop", 10)
	}
	if hasDelegateCall && hasSelfDestruct {
		addFlag("ProxyDestruction", 20)
	}
	if hasCreate2 && hasSelfDestruct {
		addFlag("MetamorphicExploit", 20)
	}
	if hasAddSubMul && !hasPanic {
		addFlag("UncheckedMath", 10)
	}
	if hasDelegateCall && hasCalldataLoad {
		addFlag("UnsafeDelegateCall", 20)
	}
	if hasDelegateCall && !hasHardcodedDelegate {
		addFlag("UnrestrictedDelegateCall", 30)
	}
	if hasReentrancyGuard {
		addFlag("ReentrancyGuard", 0)
	}
	if hasDynamicJump && hasCalldataLoad {
		addFlag("ArbitraryJump", 40)
	}
	if hasAnd && hasCalldataLoad {
		addFlag("IntegerTruncation", 10)
	}
	if hasTransferSig && hasTimestamp {
		addFlag("TradingCooldown", 10)
	}
	if hasTransferSig && hasCaller {
		addFlag("OwnerTransferCheck", 5)
	}
	if hasTransferEvent && !hasSstore {
		addFlag("FakeTransferEvent", 50)
	}
	if hasSelfDestruct && hasCaller {
		addFlag("PrivilegedSelfDestruct", 20)
	}
	if hasLoop && hasGasLimit {
		addFlag("DoSGasLimit", 15)
	}
	if hasDynamicCall && hasCalldataLoad {
		addFlag("TokenDraining", 30)
	}
	if hasEcrecover && !hasSValueCheck {
		addFlag("SignatureMalleability", 20)
	}
	if hasKeccak256 && hasEq && countSload > 0 {
		addFlag("FrontRunning", 30)
	}
	if hasSelfDestruct && (hasCreate || hasCreate2) {
		addFlag("GasTokenMinting", 40)
	}
	if hasWriteToSlotZero {
		addFlag("UninitializedPointer", 20)
	}
	if hasTransferSig && !hasIsZero && !hasEq {
		addFlag("MissingZeroCheck", 10)
	}
	if hasTransferEvent && countLogs == 0 {
		addFlag("UnusedEvent", 10)
	}
	if hasEcrecover && countSload == 0 {
		addFlag("SignatureReplay", 20)
	}
	if hasCaller && hasSstore && countSload == 0 {
		addFlag("UninitializedConstructor", 30)
	}
	if hasTransferEvent && !hasTransferSig {
		addFlag("MisleadingFunctionName", 20)
	}
	if hasBalanceOf && !hasSstore {
		addFlag("FakeHighBalance", 40)
	}
	if hasTransferSig && hasSubConstant {
		addFlag("HiddenFee", 20)
	}

	hasBurnable := false
	hasUpgradable := false
	hasOwnable := false
	hasWithdrawal := false
	for _, f := range flags {
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
	if a.hasDelegateCall && !a.hasEIP1967 {
		a.addFlag("NonStandardProxy", 20)
	}
	if a.hasDelegateCall && len(a.detected) > 0 {
		// If we detected other flags (implying selectors/features) and have delegatecall, potential clash
		// This is a heuristic approximation
		a.addFlag("ProxySelectorClash", 15)
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
