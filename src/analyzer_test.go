package main

import (
	"encoding/hex"
	"testing"
)

func TestAnalyzeCode(t *testing.T) {
	tests := []struct {
		name         string
		bytecode     string
		wantFlags    []string
		unwantFlags  []string
		wantScoreMin int
	}{
		{
			name:         "SelfDestruct",
			bytecode:     "6080604052ff", // FF is SELFDESTRUCT
			wantFlags:    []string{"SelfDestruct", "Stateless", "UnprotectedSelfDestruct"},
			wantScoreMin: 130,
		},
		{
			name:         "BadRandomness",
			bytecode:     "608060405240", // 40 is BLOCKHASH
			wantFlags:    []string{"BadRandomness", "Stateless"},
			wantScoreMin: 45,
		},
		{
			name:         "FakeToken",
			bytecode:     "608060405263a9059cbb", // PUSH4 Transfer sig (a9059cbb) + No SSTORE
			wantFlags:    []string{"Stateless", "FakeToken"},
			wantScoreMin: 80,
		},
		{
			name:         "ValidToken",
			bytecode:     "60806040525563a9059cbb", // SSTORE (55) + PUSH4 Transfer sig
			wantFlags:    []string{},               // Should NOT have Stateless or FakeToken
			wantScoreMin: 0,
		},
		{
			name:         "MintableBurnable",
			bytecode:     "6340c10f196342966c6855", // PUSH4 Mint sig + PUSH4 Burn sig + SSTORE
			wantFlags:    []string{"Mintable", "Burnable"},
			wantScoreMin: 10,
		},
		{
			name:         "LowLevelCallAndFactory",
			bytecode:     "f1f055", // CALL (F1) + CREATE (F0) + SSTORE
			wantFlags:    []string{"LowLevelCall", "ContractFactory"},
			wantScoreMin: 20,
		},
		{
			name:         "CalldataSize",
			bytecode:     "3655", // CALLDATASIZE (36) + SSTORE
			wantFlags:    []string{"CalldataSizeCheck"},
			wantScoreMin: 5,
		},
		{
			name:         "TaxToken",
			bytecode:     "63a9059cbb0455", // PUSH4 Transfer sig + DIV (04) + SSTORE
			wantFlags:    []string{"TaxToken"},
			wantScoreMin: 20,
		},
		{
			name:         "StrictBalanceEquality",
			bytecode:     "311455", // BALANCE (31) + EQ (14) + SSTORE
			wantFlags:    []string{"StrictBalanceEquality"},
			wantScoreMin: 10,
		},
		{
			name:         "UncheckedCall",
			bytecode:     "f15055", // CALL (F1) + POP (50) + SSTORE
			wantFlags:    []string{"LowLevelCall", "UncheckedCall"},
			wantScoreMin: 25, // LowLevelCall (10) + UncheckedCall (15)
		},
		{
			name:         "UncheckedDelegateCall",
			bytecode:     "f45055", // DELEGATECALL (F4) + POP (50) + SSTORE
			wantFlags:    []string{"DelegateCall", "UncheckedCall", "UncheckedDelegateCall"},
			wantScoreMin: 55, // DelegateCall (20) + UncheckedCall (15) + UncheckedDelegateCall (20)
		},
		{
			name:         "UncheckedDelegateCall_Stop",
			bytecode:     "f400", // DELEGATECALL (F4) + STOP (00)
			wantFlags:    []string{"DelegateCall", "UncheckedCall", "UncheckedDelegateCall"},
			wantScoreMin: 55,
		},
		{
			name:         "UncheckedCall_Stop",
			bytecode:     "f100", // CALL (F1) + STOP (00)
			wantFlags:    []string{"LowLevelCall", "UncheckedCall"},
			wantScoreMin: 25, // LowLevelCall (10) + UncheckedCall (15)
		},
		{
			name:         "UncheckedCallCode_Stop",
			bytecode:     "f200", // CALLCODE (F2) + STOP (00)
			wantFlags:    []string{"LowLevelCall", "UncheckedCall"},
			wantScoreMin: 25,
		},
		{
			name:         "UncheckedCreate",
			bytecode:     "f050", // CREATE (F0) + POP (50)
			wantFlags:    []string{"ContractFactory", "UncheckedCreate"},
			wantScoreMin: 30,
		},
		{
			name:         "UncheckedStaticCall_Stop",
			bytecode:     "fa00", // STATICCALL (FA) + STOP (00)
			wantFlags:    []string{"UncheckedCall"},
			wantScoreMin: 15,
		},
		{
			name:         "UncheckedStaticCall",
			bytecode:     "fa50", // STATICCALL (FA) + POP (50)
			wantFlags:    []string{"UncheckedCall"},
			wantScoreMin: 15,
		},
		{
			name:         "LockedEther",
			bytecode:     "600055", // PUSH1 00 + SSTORE (No CALL/CREATE/SELFDESTRUCT)
			wantFlags:    []string{"LockedEther"},
			wantScoreMin: 5,
		},
		{
			name:         "DivideBeforeMultiply",
			bytecode:     "0460020255", // DIV (04) + PUSH1 02 + MUL (02) + SSTORE
			wantFlags:    []string{"DivideBeforeMultiply"},
			wantScoreMin: 10,
		},
		{
			name:         "ShadowingState",
			bytecode:     "545055", // SLOAD (54) + POP (50) + SSTORE
			wantFlags:    []string{"ShadowingState"},
			wantScoreMin: 5,
		},
		{
			name:         "GasUsage",
			bytecode:     "5a55", // GAS (5A) + SSTORE
			wantFlags:    []string{"GasUsage"},
			wantScoreMin: 5,
		},
		{
			name:         "IncorrectConstructor",
			bytecode:     "63673448dd55", // PUSH4 constructor() sig + SSTORE
			wantFlags:    []string{"IncorrectConstructor"},
			wantScoreMin: 5,
		},
		{
			name:         "PotentialHoneypot",
			bytecode:     "63a9059cbb55", // PUSH4 Transfer sig + SSTORE + NO Transfer Event Topic
			wantFlags:    []string{"NoTransferEvent", "PotentialHoneypot"},
			wantScoreMin: 70,
		},
		{
			name:         "WriteToSlotZero",
			bytecode:     "600055", // PUSH1 00 + SSTORE
			wantFlags:    []string{"WriteToSlotZero", "UninitializedPointer"},
			wantScoreMin: 40,
		},
		{
			name:         "SuspiciousCodeSize",
			bytecode:     "3855", // CODESIZE + SSTORE
			wantFlags:    []string{"SuspiciousCodeSize"},
			wantScoreMin: 5,
		},
		{
			name:         "HardcodedGasLimit",
			bytecode:     "60fff155", // PUSH1 ff + CALL + SSTORE
			wantFlags:    []string{"HardcodedGasLimit", "LowLevelCall"},
			wantScoreMin: 15,
		},
		{
			name:         "ReturnBomb",
			bytecode:     "fd", // REVERT (No RETURN, No STOP)
			wantFlags:    []string{"ReturnBomb"},
			wantScoreMin: 50,
		},
		{
			name:         "ERC777Reentrancy",
			bytecode:     "600055731820a4b7618bde71dce8cdc73aab6c95905fad24", // SSTORE + PUSH20 ERC1820 Address
			wantFlags:    []string{"ERC777Reentrancy"},
			wantScoreMin: 20,
		},
		{
			name:         "UncheckedReturnData",
			bytecode:     "f155", // CALL (F1) + SSTORE (No RETURNDATASIZE 3D)
			wantFlags:    []string{"UncheckedReturnData", "LowLevelCall"},
			wantScoreMin: 20,
		},
		{
			name:         "CheckedReturnData",
			bytecode:     "f13d55",                 // CALL (F1) + RETURNDATASIZE (3D) + SSTORE
			wantFlags:    []string{"LowLevelCall"}, // Should NOT have UncheckedReturnData
			wantScoreMin: 10,
		},
		{
			name:         "WithdrawalAndRenounce",
			bytecode:     "633ccfd60b63715018a655", // PUSH4 withdraw() + PUSH4 renounceOwnership() + SSTORE
			wantFlags:    []string{"Withdrawal", "RenounceOwnership"},
			wantScoreMin: 0,
		},
		{
			name:         "LoopDetected",
			bytecode:     "5b600057", // JUMPDEST (0) + PUSH1 0 + JUMPI (Loop to 0)
			wantFlags:    []string{"LoopDetected"},
			wantScoreMin: 5,
		},
		{
			name:         "InfiniteLoop",
			bytecode:     "5b600056", // JUMPDEST (0) + PUSH1 0 + JUMP (Unconditional loop)
			wantFlags:    []string{"LoopDetected", "InfiniteLoop"},
			wantScoreMin: 25,
		},
		{
			name:         "CallInLoop",
			bytecode:     "5bf1600057", // JUMPDEST + CALL + PUSH1 0 + JUMPI
			wantFlags:    []string{"LoopDetected", "CallInLoop"},
			wantScoreMin: 15,
		},
		{
			name:         "GasDependentLoop",
			bytecode:     "5b5a600057", // JUMPDEST + GAS + PUSH1 0 + JUMPI
			wantFlags:    []string{"LoopDetected", "GasDependentLoop", "GasGriefing", "GasGriefingLoop"},
			wantScoreMin: 75,
		},
		{
			name:         "SuspiciousStateChange",
			bytecode:     "600155", // PUSH 1 + SSTORE (No SLOAD)
			wantFlags:    []string{"SuspiciousStateChange"},
			wantScoreMin: 10,
		},
		{
			name:         "NormalStateChange",
			bytecode:     "5455",     // SLOAD + SSTORE
			wantFlags:    []string{}, // Should NOT have SuspiciousStateChange
			wantScoreMin: 0,
		},
		{
			name:         "DelegateCallToZero",
			bytecode:     "6000f4", // PUSH1 0 + DELEGATECALL
			wantFlags:    []string{"DelegateCall", "DelegateCallToZero"},
			wantScoreMin: 50,
		},
		{
			name:         "CostlyLoop",
			bytecode:     "5b55600057", // JUMPDEST + SSTORE + PUSH1 0 + JUMPI
			wantFlags:    []string{"LoopDetected", "CostlyLoop"},
			wantScoreMin: 15,
		},
		{
			name:         "ProxyDestruction",
			bytecode:     "f4ff", // DELEGATECALL + SELFDESTRUCT
			wantFlags:    []string{"DelegateCall", "SelfDestruct", "ProxyDestruction"},
			wantScoreMin: 90,
		},
		{
			name:         "MetamorphicExploit",
			bytecode:     "f5ff", // CREATE2 + SELFDESTRUCT
			wantFlags:    []string{"Metamorphic", "SelfDestruct", "MetamorphicExploit"},
			wantScoreMin: 100,
		},
		{
			name:         "HardcodedSelfDestruct",
			bytecode:     "730000000000000000000000000000000000000001ff", // PUSH20 (addr) + SELFDESTRUCT
			wantFlags:    []string{"SelfDestruct", "HardcodedSelfDestruct"},
			wantScoreMin: 100,
		},
		{
			name:         "UncheckedMath",
			bytecode:     "0155", // ADD (01) + SSTORE (No Panic signature)
			wantFlags:    []string{"UncheckedMath"},
			wantScoreMin: 10,
		},
		{
			name:         "UnsafeDelegateCall",
			bytecode:     "35f4", // CALLDATALOAD (35) + DELEGATECALL (F4)
			wantFlags:    []string{"DelegateCall", "UnsafeDelegateCall"},
			wantScoreMin: 40,
		},
		{
			name:         "ReentrancyGuard",
			bytecode:     "6000556e5265656e7472616e63794775617264", // SSTORE + PUSH15 "ReentrancyGuard" string
			wantFlags:    []string{"ReentrancyGuard"},
			wantScoreMin: 0,
		},
		{
			name:         "HardcodedBlacklistedAddress",
			bytecode:     "73d90e2f925da726b50c4ed8d0fb90ad053324f31b55", // PUSH20 TornadoRouter + SSTORE
			wantFlags:    []string{"HardcodedBlacklistedAddress"},
			wantScoreMin: 50,
		},
		{
			name:         "FakeReturn",
			bytecode:     "600160005260206000f3", // PUSH1 1, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
			wantFlags:    []string{"FakeReturn", "Stateless"},
			wantScoreMin: 50,
		},
		{
			name:         "HiddenMint",
			bytecode:     "63a9059cbb330155", // PUSH4 TransferSig + CALLER (33) + ADD (01) + SSTORE (55) (No MintSig)
			wantFlags:    []string{"HiddenMint"},
			wantScoreMin: 40,
		},
		{
			name:         "GasGriefing_Invalid",
			bytecode:     "fe", // INVALID (0xFE)
			wantFlags:    []string{"GasGriefing"},
			wantScoreMin: 30,
		},
		{
			name:         "FrontRunning",
			bytecode:     "201454", // SHA3 (20) + EQ (14) + SLOAD (54)
			wantFlags:    []string{"FrontRunning", "Stateless", "LockedEther"},
			wantScoreMin: 65,
		},
		{
			name:         "SignatureMalleability",
			bytecode:     "6001fa", // PUSH1 01 + STATICCALL (FA)
			wantFlags:    []string{"UncheckedEcrecover", "SignatureMalleability", "Stateless"},
			wantScoreMin: 70,
		},
		{
			name:         "GasTokenMinting",
			bytecode:     "fff0", // SELFDESTRUCT (FF) + CREATE (F0)
			wantFlags:    []string{"SelfDestruct", "ContractFactory", "GasTokenMinting", "Stateless"},
			wantScoreMin: 130,
		},
		{
			name:         "UninitializedLocalVariables",
			bytecode:     "600054", // PUSH1 00 + SLOAD
			wantFlags:    []string{"UninitializedLocalVariables"},
			wantScoreMin: 20,
		},
		{
			name:         "AssemblyErrorProne_MSIZE",
			bytecode:     "59", // MSIZE
			wantFlags:    []string{"AssemblyErrorProne"},
			wantScoreMin: 10,
		},
		{
			name:         "AssemblyErrorProne_StorageToMemory",
			bytecode:     "5451", // SLOAD (54) + MLOAD (51)
			wantFlags:    []string{"AssemblyErrorProne"},
			wantScoreMin: 20,
		},
		{
			name:         "UnusedEvent",
			bytecode:     "7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // PUSH32 TransferTopic (no LOG)
			wantFlags:    []string{"UnusedEvent"},
			wantScoreMin: 10,
		},
		{
			name:         "SignatureReplay",
			bytecode:     "6001fa", // PUSH1 1 + STATICCALL (Precompile 1 = ecrecover) + No SLOAD
			wantFlags:    []string{"SignatureReplay"},
			wantScoreMin: 20,
		},
		{
			name:         "TimestampDependence",
			bytecode:     "42", // TIMESTAMP
			wantFlags:    []string{"TimestampDependence"},
			wantScoreMin: 5,
		},
		{
			name:         "UnrestrictedDelegateCall",
			bytecode:     "6000f4", // PUSH1 0 + DELEGATECALL
			wantFlags:    []string{"UnrestrictedDelegateCall"},
			wantScoreMin: 30,
		},
		{
			name:         "UninitializedConstructor",
			bytecode:     "3355", // CALLER (33) + SSTORE (55) + No SLOAD
			wantFlags:    []string{"UninitializedConstructor"},
			wantScoreMin: 30,
		},
		{
			name:         "MisleadingFunctionName",
			bytecode:     "7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60006000a1", // PUSH32 TransferTopic + LOG1 (no TransferSig)
			wantFlags:    []string{"MisleadingFunctionName"},
			wantScoreMin: 20,
		},
		{
			name:         "FakeHighBalance",
			bytecode:     "60806040526370a08231", // PUSH4 balanceOf (no SSTORE)
			wantFlags:    []string{"FakeHighBalance", "Stateless"},
			wantScoreMin: 40,
		},
		{
			name:         "HiddenFee",
			bytecode:     "63a9059cbb600103", // PUSH4 TransferSig + PUSH1 1 + SUB
			wantFlags:    []string{"HiddenFee"},
			wantScoreMin: 20,
		},
		{
			name:         "PhantomFunction",
			bytecode:     "633ccfd60b00", // PUSH4 withdraw() + STOP (No ETH sending opcodes)
			wantFlags:    []string{"Withdrawal", "PhantomFunction"},
			wantScoreMin: 40,
		},
		{
			name:         "StrawManContract",
			bytecode:     "633ccfd60bfd", // PUSH4 withdraw() + REVERT
			wantFlags:    []string{"Withdrawal", "StrawManContract"},
			wantScoreMin: 50,
		},
		{
			name:         "NonStandardProxy",
			bytecode:     "6000f4", // DELEGATECALL (no EIP-1967 slots)
			wantFlags:    []string{"DelegateCall", "NonStandardProxy"},
			wantScoreMin: 20,
		},
		{
			name:         "GasGriefingLoop",
			bytecode:     "5b600056", // Infinite Loop
			wantFlags:    []string{"InfiniteLoop", "GasGriefingLoop"},
			wantScoreMin: 30,
		},
		{
			name:         "UnprotectedEtherWithdrawal",
			bytecode:     "633ccfd60bf1", // PUSH4 withdraw() + CALL (no SLOAD)
			wantFlags:    []string{"Withdrawal", "UnprotectedEtherWithdrawal", "LowLevelCall"},
			wantScoreMin: 50,
		},
		{
			name:         "ReentrancyNoGasLimit",
			bytecode:     "5af1", // GAS + CALL
			wantFlags:    []string{"ReentrancyNoGasLimit", "LowLevelCall", "GasUsage"},
			wantScoreMin: 30,
		},
		{
			name:         "BlockTimestampManipulation",
			bytecode:     "42600011", // TIMESTAMP (42) + PUSH1 00 + GT (11)
			wantFlags:    []string{"TimestampDependence", "BlockTimestampManipulation"},
			wantScoreMin: 15,
		},
		{
			name:         "DelegateCallToSelf",
			bytecode:     "30f4", // ADDRESS (30) + DELEGATECALL (F4)
			wantFlags:    []string{"DelegateCall", "DelegateCallToSelf"},
			wantScoreMin: 50,
		},
		{
			name:         "UninitializedState",
			bytecode:     "600054600055", // PUSH1 00 + SLOAD + PUSH1 00 + SSTORE (Read before Write)
			wantFlags:    []string{"UninitializedState", "UninitializedLocalVariables"},
			wantScoreMin: 40,
		},
		{
			name:         "TxOrigin",
			bytecode:     "32", // ORIGIN
			wantFlags:    []string{"TxOrigin", "Stateless"},
			wantScoreMin: 40,
		},
		{
			name:         "PrivilegedSelfDestruct",
			bytecode:     "33ff", // CALLER + SELFDESTRUCT
			wantFlags:    []string{"SelfDestruct", "PrivilegedSelfDestruct", "Stateless", "UnprotectedSelfDestruct"},
			wantScoreMin: 100,
		},
		{
			name:         "UncheckedTransfer",
			bytecode:     "63a9059cbb6000f150", // PUSH4 transferSig + PUSH1 0 + CALL + POP (Unchecked)
			wantFlags:    []string{"LowLevelCall", "UncheckedTransfer", "UncheckedCall"},
			wantScoreMin: 45,
		},
		{
			name:         "UncheckedTransferFrom",
			bytecode:     "6323b872ddf150", // PUSH4 transferFromSig + CALL + POP
			wantFlags:    []string{"LowLevelCall", "UncheckedTransferFrom", "UncheckedCall"},
			wantScoreMin: 45,
		},
		{
			name:         "ZeroAddressTransfer",
			bytecode:     "7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef6000a3", // PUSH32 TransferTopic + PUSH1 0 + LOG3
			wantFlags:    []string{"ZeroAddressTransfer"},
			wantScoreMin: 10,
		},
		{
			name:         "ReinitializableProxy",
			bytecode:     "638129fc1c55", // PUSH4 initialize() (0x8129fc1c) + SSTORE
			wantFlags:    []string{"ReinitializableProxy"},
			wantScoreMin: 20,
		},
		{
			name:         "ReadOnlyReentrancy",
			bytecode:     "fa54", // STATICCALL (FA) + SLOAD (54)
			wantFlags:    []string{"ReadOnlyReentrancy"},
			wantScoreMin: 30,
		},
		{
			name:         "ReadOnlyReentrancy_WithPadding",
			bytecode:     "fa505054", // STATICCALL + POP + POP + SLOAD (within 10-byte window)
			wantFlags:    []string{"ReadOnlyReentrancy"},
			wantScoreMin: 30,
		},
		{
			name:         "EIP1822_UUPS",
			bytecode:     "7fc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf75554f4", // PUSH32 PROXIABLE_SLOT + SSTORE + SLOAD + DELEGATECALL
			wantFlags:    []string{"DelegateCall"},                                                   // Should NOT have NonStandardProxy
			wantScoreMin: 20,
		},
		{
			name:         "EIP1167_MinimalProxy",
			bytecode:     "363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3",
			wantFlags:    []string{"MinimalProxy", "DelegateCall"}, // Should NOT have NonStandardProxy
			wantScoreMin: 20,
		},
		{
			name:         "ArbitraryStorageWrite",
			bytecode:     "3555", // CALLDATALOAD (35) + SSTORE (55)
			wantFlags:    []string{"ArbitraryStorageWrite"},
			wantScoreMin: 30,
		},
		{
			name:         "MissingReturn",
			bytecode:     "63a9059cbb5500", // PUSH4 Transfer + SSTORE + STOP (No RETURN)
			wantFlags:    []string{"MissingReturn"},
			wantScoreMin: 20,
		},
		{
			name:         "MissingZeroCheck",
			bytecode:     "63a9059cbb55", // TransferSig + SSTORE (No ISZERO/EQ)
			wantFlags:    []string{"MissingZeroCheck"},
			wantScoreMin: 10,
		},
		{
			name:         "TokenDraining",
			bytecode:     "35f1", // CALLDATALOAD + CALL (Dynamic)
			wantFlags:    []string{"TokenDraining"},
			wantScoreMin: 30,
		},
		{
			name:         "ArbitraryJump",
			bytecode:     "3556", // CALLDATALOAD + JUMP
			wantFlags:    []string{"ArbitraryJump"},
			wantScoreMin: 40,
		},
		{
			name:         "IntegerTruncation",
			bytecode:     "3516", // CALLDATALOAD + AND
			wantFlags:    []string{"IntegerTruncation"},
			wantScoreMin: 10,
		},
		{
			name:         "PublicBurn",
			bytecode:     "6342966c6855", // Burnable sig + SSTORE (No Ownable)
			wantFlags:    []string{"PublicBurn"},
			wantScoreMin: 30,
		},
		{
			name:         "UnprotectedUpgrade",
			bytecode:     "633659cfe655", // Upgradable sig + SSTORE (No Ownable)
			wantFlags:    []string{"UnprotectedUpgrade"},
			wantScoreMin: 40,
		},
		{
			name:         "ProxySelectorClash",
			bytecode:     "6340c10f1955f4", // Mintable sig + SSTORE + DELEGATECALL
			wantFlags:    []string{"ProxySelectorClash"},
			wantScoreMin: 15,
		},
		{
			name:         "SuspiciousDelegate",
			bytecode:     "73fffffffffffffffffffffffffffffffffffffffff4", // PUSH20 + DELEGATECALL
			wantFlags:    []string{"SuspiciousDelegate"},
			wantScoreMin: 30,
		},
		{
			name:         "DoSGasLimit",
			bytecode:     "5b45600057", // JUMPDEST + GASLIMIT + PUSH 0 + JUMPI (Loop)
			wantFlags:    []string{"DoSGasLimit"},
			wantScoreMin: 15,
		},
		{
			name:         "DeadCode",
			bytecode:     "006000", // STOP + PUSH1 00 (Unreachable)
			wantFlags:    []string{"DeadCode"},
			wantScoreMin: 5,
		},
		{
			name:         "WeakRandomness",
			bytecode:     "44", // DIFFICULTY
			wantFlags:    []string{"WeakRandomness"},
			wantScoreMin: 10,
		},
		{
			name:         "BlockStuffing",
			bytecode:     "45", // GASLIMIT
			wantFlags:    []string{"BlockStuffing"},
			wantScoreMin: 5,
		},
		{
			name:         "AntiContractCheck",
			bytecode:     "3b", // EXTCODESIZE
			wantFlags:    []string{"AntiContractCheck"},
			wantScoreMin: 10,
		},
		{
			name:         "CodeHashCheck",
			bytecode:     "3f", // EXTCODEHASH
			wantFlags:    []string{"CodeHashCheck"},
			wantScoreMin: 10,
		},
		{
			name:         "Ownable",
			bytecode:     "63f2fde38b", // Ownable sig
			wantFlags:    []string{"Ownable"},
			wantScoreMin: 0,
		},
		{
			name:         "Blacklist",
			bytecode:     "631d3b9edf", // Blacklist sig
			wantFlags:    []string{"Blacklist"},
			wantScoreMin: 20,
		},
		{
			name:         "InterfaceCheck",
			bytecode:     "6301ffc9a7", // ERC165 sig
			wantFlags:    []string{"InterfaceCheck"},
			wantScoreMin: 0,
		},
		{
			name:         "FlashLoan",
			bytecode:     "635cffe9de", // FlashLoan sig
			wantFlags:    []string{"FlashLoan"},
			wantScoreMin: 0,
		},
		{
			name:         "DelegateCallInLoop",
			bytecode:     "5bf4600057", // JUMPDEST + DELEGATECALL + PUSH 0 + JUMPI
			wantFlags:    []string{"LoopDetected", "DelegateCallInLoop", "DelegateCall"},
			wantScoreMin: 25,
		},
		{
			name:         "FactoryInLoop",
			bytecode:     "5bf0600057", // JUMPDEST + CREATE + PUSH 0 + JUMPI
			wantFlags:    []string{"LoopDetected", "FactoryInLoop", "ContractFactory"},
			wantScoreMin: 25,
		},
		{
			name:         "SelfDestructInLoop",
			bytecode:     "5bff600057", // JUMPDEST + SELFDESTRUCT + PUSH 0 + JUMPI
			wantFlags:    []string{"LoopDetected", "SelfDestructInLoop", "SelfDestruct"},
			wantScoreMin: 55,
		},
		{
			name:         "GasPriceCheck",
			bytecode:     "3a", // GASPRICE
			wantFlags:    []string{"GasPriceCheck"},
			wantScoreMin: 5,
		},
		{
			name:         "CoinbaseCheck",
			bytecode:     "41", // COINBASE
			wantFlags:    []string{"CoinbaseCheck"},
			wantScoreMin: 5,
		},
		{
			name:         "BlockNumberCheck",
			bytecode:     "43", // NUMBER
			wantFlags:    []string{"BlockNumberCheck"},
			wantScoreMin: 5,
		},
		{
			name:         "ChainIDCheck",
			bytecode:     "46", // CHAINID
			wantFlags:    []string{"ChainIDCheck"},
			wantScoreMin: 5,
		},
		{
			name:         "CheckOwnBalance",
			bytecode:     "47", // SELFBALANCE
			wantFlags:    []string{"CheckOwnBalance"},
			wantScoreMin: 5,
		},
		{
			name:         "TradingCooldown",
			bytecode:     "63a9059cbb42", // TransferSig + TIMESTAMP
			wantFlags:    []string{"TradingCooldown", "TimestampDependence"},
			wantScoreMin: 15,
		},
		{
			name:         "OwnerTransferCheck",
			bytecode:     "63a9059cbb33", // TransferSig + CALLER
			wantFlags:    []string{"OwnerTransferCheck"},
			wantScoreMin: 5,
		},
		{
			name:         "FakeTransferEvent",
			bytecode:     "7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60006000a1", // Topic + LOG1 (No SSTORE)
			wantFlags:    []string{"FakeTransferEvent"},
			wantScoreMin: 50,
		},
		{
			name:         "NestedLoops",
			bytecode:     "5b60015b600357600057", // Nested loops: JUMPDEST(0) ... JUMPDEST(3) ... JUMPI(3) ... JUMPI(0)
			wantFlags:    []string{"LoopDetected"},
			wantScoreMin: 5,
		},
		{
			name: "IrreducibleControlFlow",
			// A "spaghetti" flow with multiple entries into the loop structure.
			// 00: PUSH1 06 (L1) -> JUMPI (Entry 1)
			// 03: PUSH1 0A (L2) -> JUMP  (Entry 2)
			// 06: JUMPDEST (L1)
			// 07: PUSH1 0A (L2) -> JUMP  (L1 -> L2)
			// 0A: JUMPDEST (L2)
			// 0B: PUSH1 06 (L1) -> JUMP  (L2 -> L1) [Backward Jump detected here]
			bytecode:     "600657600a565b600a565b600656",
			wantFlags:    []string{"LoopDetected", "InfiniteLoop"},
			wantScoreMin: 25,
		},
		{
			name:         "DelegateCallToZero_PUSH0",
			bytecode:     "5ff4", // PUSH0 (5F) + DELEGATECALL (F4)
			wantFlags:    []string{"DelegateCall", "DelegateCallToZero"},
			wantScoreMin: 50,
		},
		{
			name:         "UncheckedEcrecover_Explicit",
			bytecode:     "6001fa", // PUSH1 1 + STATICCALL
			wantFlags:    []string{"UncheckedEcrecover"},
			wantScoreMin: 20,
		},
		{
			name:         "SignatureReplay_WithMemory",
			bytecode:     "6001fa600051", // PUSH1 1 + STATICCALL + PUSH1 0 + MLOAD (No SLOAD)
			wantFlags:    []string{"SignatureReplay"},
			wantScoreMin: 20,
		},
		{
			name:         "TxOriginPhishing",
			bytecode:     "326000f1", // ORIGIN (32) + PUSH 0 + CALL (F1)
			wantFlags:    []string{"TxOrigin", "TxOriginPhishing", "LowLevelCall"},
			wantScoreMin: 70,
		},
		{
			name:         "BitwiseLogic",
			bytecode:     "60011b", // PUSH 1 + SHL (1B)
			wantFlags:    []string{"BitwiseLogic"},
			wantScoreMin: 5,
		},
		{
			name:         "HiddenApproval",
			bytecode:     "63095ea7b355", // PUSH4 approve() + SSTORE (No TransferSig)
			wantFlags:    []string{"HiddenApproval"},
			wantScoreMin: 20,
		},
		{
			name:         "FlashLoanReceiver",
			bytecode:     "6310d1e85c", // PUSH4 onFlashLoan
			wantFlags:    []string{"FlashLoanReceiver"},
			wantScoreMin: 10,
		},
		{
			name:         "TxOrigin_SafeDistance",
			bytecode:     "325050505050505050505050505050505050505050f1", // ORIGIN + 20 POPs + CALL
			wantFlags:    []string{"TxOrigin", "LowLevelCall"},
			unwantFlags:  []string{"TxOriginPhishing"},
			wantScoreMin: 20,
		},
		{
			name:         "TxOrigin_Boundary_Safe",
			bytecode:     "3250505050505050505050505050505050505050f1", // ORIGIN + 19 POPs + CALL (Dist 20)
			wantFlags:    []string{"TxOrigin", "LowLevelCall"},
			unwantFlags:  []string{"TxOriginPhishing"},
			wantScoreMin: 20,
		},
		{
			name:         "TxOrigin_Boundary_Trigger",
			bytecode:     "32505050505050505050505050505050505050f1", // ORIGIN + 18 POPs + CALL (Dist 19)
			wantFlags:    []string{"TxOrigin", "LowLevelCall", "TxOriginPhishing"},
			wantScoreMin: 70,
		},
		{
			name:         "SelfDestructNoOwner",
			bytecode:     "ff", // SELFDESTRUCT (No Ownable Sig)
			wantFlags:    []string{"SelfDestruct", "SelfDestructNoOwner"},
			wantScoreMin: 80,
		},
		{
			name:         "UncheckedCall_IgnoredReturnValue",
			bytecode:     "6000600060006000600030f150", // CALL (F1) + POP (50)
			wantFlags:    []string{"LowLevelCall", "UncheckedCall"},
			wantScoreMin: 25,
		},
		{
			name:         "UncheckedLowLevelCall_CustomGas",
			bytecode:     "6010f150", // PUSH1 16 + CALL + POP
			wantFlags:    []string{"LowLevelCall", "UncheckedCall", "UncheckedLowLevelCall"},
			wantScoreMin: 45,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _ := hex.DecodeString(tt.bytecode)
			flags, score := AnalyzeCode(code)

			for _, want := range tt.wantFlags {
				found := false
				for _, got := range flags {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("AnalyzeCode() missing flag %v. Got: %v", want, flags)
				}
			}

			for _, unwanted := range tt.unwantFlags {
				for _, got := range flags {
					if got == unwanted {
						t.Errorf("AnalyzeCode() found unwanted flag %v", unwanted)
					}
				}
			}

			if score < tt.wantScoreMin {
				t.Errorf("AnalyzeCode() score = %v, want >= %v", score, tt.wantScoreMin)
			}
		})
	}
}

func TestAnalyzer_StateIsolation(t *testing.T) {
	// 1. Analyze code with SelfDestruct
	code1, _ := hex.DecodeString("ff") // SELFDESTRUCT
	analyzer := NewAnalyzer(code1)
	flags1, _ := analyzer.Analyze()

	found := false
	for _, f := range flags1 {
		if f == "SelfDestruct" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Expected SelfDestruct in first run")
	}

	// 2. Reset and analyze code without SelfDestruct
	code2, _ := hex.DecodeString("00") // STOP
	analyzer.Reset(code2)

	// Verify internal state cleared
	if analyzer.hasSelfDestruct {
		t.Error("hasSelfDestruct should be false after Reset")
	}
	if len(analyzer.detected) != 0 {
		t.Error("detected map should be empty after Reset")
	}

	flags2, _ := analyzer.Analyze()
	for _, f := range flags2 {
		if f == "SelfDestruct" {
			t.Error("SelfDestruct persisted after Reset")
		}
	}
}

func TestAnalyzer_ConfigurableHeuristics(t *testing.T) {
	code, _ := hex.DecodeString("ff") // SELFDESTRUCT

	// 1. Default (All enabled)
	a1 := NewAnalyzer(code)
	flags1, _ := a1.Analyze()
	if len(flags1) == 0 || flags1[0] != "SelfDestruct" {
		t.Error("Expected SelfDestruct to be enabled by default")
	}

	// 2. Explicit Disable
	a2 := NewAnalyzer(code)
	disabled := map[string]bool{"SelfDestruct": true}
	a2.UpdateHeuristics(nil, disabled)
	flags2, _ := a2.Analyze()
	for _, f := range flags2 {
		if f == "SelfDestruct" {
			t.Error("Expected SelfDestruct to be disabled")
		}
	}

	// 3. Explicit Enable (Allowlist)
	a3 := NewAnalyzer(code)
	enabled := map[string]bool{"Stateless": true} // Only enable Stateless, implicitly disable SelfDestruct
	a3.UpdateHeuristics(enabled, nil)
	flags3, _ := a3.Analyze()
	hasSelfDestruct := false
	for _, f := range flags3 {
		if f == "SelfDestruct" {
			hasSelfDestruct = true
		}
	}
	if hasSelfDestruct {
		t.Error("Expected SelfDestruct to be disabled via allowlist")
	}
}

func BenchmarkAnalyzeCode(b *testing.B) {
	// Simulate a complex contract bytecode with various opcodes and signatures
	code, _ := hex.DecodeString("60806040526004361061005760003560e01c8063a9059cbb1461005c57806370a0823114610089575b600080fd5b6100876004803603604081101561007257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506100a1565b005b6100876004803603602081101561009f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061012d565b600055565b6000549056")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzeCode(code)
	}
}

func BenchmarkAnalyzer_Reuse(b *testing.B) {
	// Simulate a complex contract bytecode with various opcodes and signatures
	code, _ := hex.DecodeString("60806040526004361061005760003560e01c8063a9059cbb1461005c57806370a0823114610089575b600080fd5b6100876004803603604081101561007257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506100a1565b005b6100876004803603602081101561009f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061012d565b600055565b6000549056")

	analyzer := NewAnalyzer(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Reset(code)
		analyzer.Analyze()
	}
}

func BenchmarkAnalyzer_TxOriginPhishing_Disabled(b *testing.B) {
	// Same bytecode as TxOriginPhishing but with the heuristic disabled
	bytecode := "326000f1"
	var buffer string
	for i := 0; i < 1000; i++ {
		buffer += bytecode
	}
	code, _ := hex.DecodeString(buffer)

	analyzer := NewAnalyzer(nil)
	disabled := map[string]bool{"TxOriginPhishing": true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Reset(code)
		analyzer.UpdateHeuristics(nil, disabled)
		analyzer.Analyze()
	}
}

func BenchmarkAnalyzeCode_Heavy(b *testing.B) {
	// Construct a heavy bytecode payload that triggers multiple heuristics:
	// - Loops (JUMPDEST ... JUMPI)
	// - Storage operations (SLOAD, SSTORE)
	// - External calls (DELEGATECALL, CALL)
	// - Environmental checks (TIMESTAMP, GASPRICE)
	// - Pattern matching (Push data)

	// 5b (JUMPDEST) + 6000 (PUSH1 0) + 54 (SLOAD) + 6001 (PUSH1 1) + 01 (ADD) +
	// 6000 (PUSH1 0) + 55 (SSTORE) + 30 (ADDRESS) + f4 (DELEGATECALL) +
	// 42 (TIMESTAMP) + 50 (POP) + 6000 (PUSH1 0) + 57 (JUMPI - back to 0) +
	// 63a9059cbb (PUSH4 Transfer) + 50 (POP)
	heavyBytecode := "5b60005460010160005530f4425060005763a9059cbb50"
	var buffer string
	for i := 0; i < 100; i++ {
		buffer += heavyBytecode
	}
	code, _ := hex.DecodeString(buffer)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzeCode(code)
	}
}

func BenchmarkAnalyzer_Heavy_Reuse(b *testing.B) {
	heavyBytecode := "5b60005460010160005530f4425060005763a9059cbb50"
	var buffer string
	for i := 0; i < 100; i++ {
		buffer += heavyBytecode
	}
	code, _ := hex.DecodeString(buffer)

	analyzer := NewAnalyzer(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Reset(code)
		analyzer.Analyze()
	}
}

func BenchmarkBytesToInt(b *testing.B) {
	// Simulate a 32-byte storage key (common in SSTORE/SLOAD)
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytesToInt(input)
	}
}

func BenchmarkAnalyzer_FlashLoanReceiver(b *testing.B) {
	// PUSH4 0x10d1e85c (onFlashLoan) repeated to stress test selector lookup
	bytecode := "6310d1e85c"
	var buffer string
	for i := 0; i < 1000; i++ {
		buffer += bytecode
	}
	code, _ := hex.DecodeString(buffer)

	analyzer := NewAnalyzer(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Reset(code)
		analyzer.Analyze()
	}
}

func BenchmarkAnalyzer_TxOriginPhishing(b *testing.B) {
	// ORIGIN (32) + PUSH1 0 (6000) + CALL (F1)
	// This sequence triggers TxOriginPhishing because CALL follows ORIGIN within 20 bytes.
	bytecode := "326000f1"
	var buffer string
	for i := 0; i < 1000; i++ {
		buffer += bytecode
	}
	code, _ := hex.DecodeString(buffer)

	analyzer := NewAnalyzer(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Reset(code)
		analyzer.Analyze()
	}
}
