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
			wantFlags:    []string{"UncheckedLowLevelCall", "UncheckedReturn", "UncheckedCall"},
			wantScoreMin: 55, // LowLevelCall (10) + UncheckedLowLevelCall (15) + UncheckedReturn (15) + UncheckedCall (15)
		},
		{
			name:         "UncheckedDelegateCall",
			bytecode:     "f45055", // DELEGATECALL (F4) + POP (50) + SSTORE
			wantFlags:    []string{"UncheckedLowLevelCall", "DelegateCall", "UncheckedReturn", "UncheckedCall"},
			wantScoreMin: 65, // DelegateCall (20) + UncheckedLowLevelCall (15) + UncheckedReturn (15) + UncheckedCall (15)
		},
		{
			name:         "UncheckedStaticCall",
			bytecode:     "fa50", // STATICCALL (FA) + POP (50)
			wantFlags:    []string{"UncheckedLowLevelCall", "UncheckedReturn", "UncheckedCall"},
			wantScoreMin: 45,
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
			wantFlags:    []string{"WriteToSlotZero"},
			wantScoreMin: 20,
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
			wantFlags:    []string{"LoopDetected", "GasDependentLoop"},
			wantScoreMin: 15,
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
			wantFlags:    []string{"SelfDestruct", "PrivilegedSelfDestruct", "Stateless"},
			wantScoreMin: 100,
		},
		{
			name:         "UncheckedTransfer",
			bytecode:     "63a9059cbb6000f150", // PUSH4 transferSig + PUSH1 0 + CALL + POP (Unchecked)
			wantFlags:    []string{"UncheckedLowLevelCall", "UncheckedTransfer", "UncheckedReturn", "UncheckedCall"},
			wantScoreMin: 65,
		},
		{
			name:         "ZeroAddressTransfer",
			bytecode:     "7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef6000a3", // PUSH32 TransferTopic + PUSH1 0 + LOG3
			wantFlags:    []string{"ZeroAddressTransfer"},
			wantScoreMin: 10,
		},
		{
			name:         "UncheckedTransfer",
			bytecode:     "63a9059cbb6000f150", // PUSH4 transferSig + PUSH1 0 + CALL + POP
			wantFlags:    []string{"UncheckedLowLevelCall", "UncheckedTransfer", "UncheckedReturn", "UncheckedCall"},
			wantScoreMin: 65,
		},
		{
			name:         "ZeroAddressTransfer",
			bytecode:     "7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef6000a3", // PUSH32 TransferTopic + PUSH1 0 + LOG3
			wantFlags:    []string{"ZeroAddressTransfer"},
			wantScoreMin: 10,
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
