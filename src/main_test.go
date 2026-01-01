package main

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/prometheus/client_golang/prometheus"
)

func TestDetectTokenType(t *testing.T) {
	tests := []struct {
		name     string
		bytecode string
		want     string
	}{
		{"ERC20", "608060405234801561001057600080fd5b50a9059cbb", "ERC20"},
		{"ERC721", "608060405280ac58cd", "ERC721"},
		{"ERC1155", "6080604052d9b67a26", "ERC1155"},
		{"Unknown", "6080604052", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _ := hex.DecodeString(tt.bytecode)
			if got := detectTokenType(code); got != tt.want {
				t.Errorf("detectTokenType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWatcher_ReloadConfig(t *testing.T) {
	// Setup temp config file
	tmpFile, err := os.CreateTemp("", "eth-watch-config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	configPath := tmpFile.Name()

	// Initial Config
	initialConfig := `{
		"rpc": [{"url": "http://rpc1"}],
		"whale_threshold": "100",
		"events": {"transfers": true}
	}`
	if _, err := tmpFile.WriteString(initialConfig); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Setup Watcher
	w := &Watcher{
		configPath: configPath,
		tracked:    make(map[string]*ContractState),
	}

	// Load initial config
	w.loadConfig(configPath)

	// Initialize RPC states manually as main() does
	w.rpcStates = make([]*RPCState, len(w.cfg.RPC))
	for i, rpc := range w.cfg.RPC {
		w.rpcStates[i] = &RPCState{URL: rpc.URL}
	}

	// Verify initial state
	if w.cfg.WhaleThreshold != "100" {
		t.Errorf("Initial WhaleThreshold = %s, want 100", w.cfg.WhaleThreshold)
	}
	if len(w.rpcStates) != 1 || w.rpcStates[0].URL != "http://rpc1" {
		t.Errorf("Initial RPC state incorrect")
	}

	// Modify Config File
	newConfig := `{
		"rpc": [{"url": "http://rpc1"}, {"url": "http://rpc2"}],
		"whale_threshold": "200",
		"events": {"transfers": false, "liquidity": true}
	}`
	if err := os.WriteFile(configPath, []byte(newConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Mock sessCancel to verify it's called
	cancelCalled := false
	w.sessCancel = func() { cancelCalled = true }

	// Trigger Reload
	w.reloadConfig()

	// Verify Updates
	if w.cfg.WhaleThreshold != "200" {
		t.Errorf("Reloaded WhaleThreshold = %s, want 200", w.cfg.WhaleThreshold)
	}
	if w.whaleThreshold.Cmp(big.NewInt(200)) != 0 {
		t.Errorf("Reloaded whaleThreshold big.Int = %v, want 200", w.whaleThreshold)
	}
	if len(w.rpcStates) != 2 {
		t.Errorf("Reloaded RPC states len = %d, want 2", len(w.rpcStates))
	}
	if !cancelCalled {
		t.Error("sessCancel was not called during reload")
	}
}

// MockEthClient implements EthClient for testing
type MockEthClient struct {
	ChainIDFunc             func(ctx context.Context) (*big.Int, error)
	BlockNumberFunc         func(ctx context.Context) (uint64, error)
	CloseFunc               func()
	SubscribeNewHeadFunc    func(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error)
	BlockByHashFunc         func(ctx context.Context, hash common.Hash) (*types.Block, error)
	TransactionReceiptFunc  func(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CodeAtFunc              func(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	SubscribeFilterLogsFunc func(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)
}

func (m *MockEthClient) ChainID(ctx context.Context) (*big.Int, error) {
	if m.ChainIDFunc != nil {
		return m.ChainIDFunc(ctx)
	}
	return big.NewInt(1), nil
}

func (m *MockEthClient) BlockNumber(ctx context.Context) (uint64, error) {
	if m.BlockNumberFunc != nil {
		return m.BlockNumberFunc(ctx)
	}
	return 100, nil
}

func (m *MockEthClient) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}

func (m *MockEthClient) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
	if m.SubscribeNewHeadFunc != nil {
		return m.SubscribeNewHeadFunc(ctx, ch)
	}
	return &MockSubscription{errChan: make(chan error)}, nil
}

func (m *MockEthClient) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	if m.BlockByHashFunc != nil {
		return m.BlockByHashFunc(ctx, hash)
	}
	return nil, nil
}

func (m *MockEthClient) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	if m.TransactionReceiptFunc != nil {
		return m.TransactionReceiptFunc(ctx, txHash)
	}
	return &types.Receipt{}, nil
}

func (m *MockEthClient) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	if m.CodeAtFunc != nil {
		return m.CodeAtFunc(ctx, account, blockNumber)
	}
	return []byte{}, nil
}

func (m *MockEthClient) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	if m.SubscribeFilterLogsFunc != nil {
		return m.SubscribeFilterLogsFunc(ctx, q, ch)
	}
	return &MockSubscription{errChan: make(chan error)}, nil
}

type MockSubscription struct {
	errChan chan error
}

func (m *MockSubscription) Unsubscribe() {}
func (m *MockSubscription) Err() <-chan error {
	return m.errChan
}

func TestWatcher_Run_RPCRotation(t *testing.T) {
	// Setup temporary output file
	tmpFile, err := os.CreateTemp("", "eth-watch-test-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	// Setup Watcher
	w := &Watcher{
		cfg: Config{
			RPC: []RPCConfig{
				{URL: "rpc1"},
				{URL: "rpc2"},
				{URL: "rpc3"},
			},
			Output: tmpFile.Name(),
			// Events: default zero value (all false) to simplify test
		},
		tracked: make(map[string]*ContractState),
		promMetrics: WatcherMetrics{
			ContractsDiscovered:    prometheus.NewCounter(prometheus.CounterOpts{}),
			MintsDetected:          prometheus.NewCounter(prometheus.CounterOpts{}),
			LiquidityEvents:        prometheus.NewCounter(prometheus.CounterOpts{}),
			TradesDetected:         prometheus.NewCounter(prometheus.CounterOpts{}),
			FlashLoansDetected:     prometheus.NewCounter(prometheus.CounterOpts{}),
			ApprovalsDetected:      prometheus.NewCounter(prometheus.CounterOpts{}),
			RPCStalled:             prometheus.NewGauge(prometheus.GaugeOpts{}),
			ActiveRPC:              prometheus.NewGaugeVec(prometheus.GaugeOpts{}, []string{"url"}),
			RPCLatency:             prometheus.NewHistogram(prometheus.HistogramOpts{}),
			RPCCircuitBreakerTrips: prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"url"}),
			CodeAnalysisFlags:      prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"flag"}),
			ChainIDFetchFailures:   prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"url"}),
			CodeAnalysisDuration:   prometheus.NewHistogram(prometheus.HistogramOpts{}),
		},
	}

	// Initialize RPC states
	w.rpcStates = make([]*RPCState, len(w.cfg.RPC))
	for i, rpc := range w.cfg.RPC {
		w.rpcStates[i] = &RPCState{URL: rpc.URL}
	}

	// Track calls
	var callLock sync.Mutex
	calls := make([]string, 0)

	// Mock Factory
	w.clientFactory = func(url string) (EthClient, error) {
		callLock.Lock()
		calls = append(calls, url)
		callLock.Unlock()

		if url == "rpc1" {
			return nil, errors.New("connection failed")
		}
		if url == "rpc2" {
			// Return client that fails ChainID
			return &MockEthClient{
				ChainIDFunc: func(ctx context.Context) (*big.Int, error) {
					return nil, errors.New("chain id failed")
				},
				CloseFunc: func() {},
			}, nil
		}
		if url == "rpc3" {
			// Return working client
			return &MockEthClient{
				ChainIDFunc: func(ctx context.Context) (*big.Int, error) {
					return big.NewInt(1), nil
				},
				BlockNumberFunc: func(ctx context.Context) (uint64, error) {
					return 100, nil
				},
				SubscribeNewHeadFunc: func(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
					return &MockSubscription{errChan: make(chan error)}, nil
				},
				CloseFunc: func() {},
			}, nil
		}
		return nil, errors.New("unknown rpc")
	}

	// Run with timeout to ensure test exits
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	w.Run(ctx)

	callLock.Lock()
	defer callLock.Unlock()

	// Verify order: rpc1 (fail), rpc2 (fail chainid), rpc3 (success)
	if len(calls) < 3 {
		t.Fatalf("Expected at least 3 RPC calls, got %d: %v", len(calls), calls)
	}

	if calls[0] != "rpc1" {
		t.Errorf("Expected first call to rpc1, got %s", calls[0])
	}
	if calls[1] != "rpc2" {
		t.Errorf("Expected second call to rpc2, got %s", calls[1])
	}
	if calls[2] != "rpc3" {
		t.Errorf("Expected third call to rpc3, got %s", calls[2])
	}
}

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
			wantFlags:    []string{"SelfDestruct", "Stateless"},
			wantScoreMin: 80,
		},
		{
			name:         "BadRandomness",
			bytecode:     "608060405240", // 40 is BLOCKHASH
			wantFlags:    []string{"BadRandomness", "Stateless"},
			wantScoreMin: 45,
		},
		{
			name:         "FakeToken",
			bytecode:     "6080604052a9059cbb", // Transfer sig (a9059cbb) + No SSTORE
			wantFlags:    []string{"Stateless", "FakeToken"},
			wantScoreMin: 80,
		},
		{
			name:         "ValidToken",
			bytecode:     "608060405255a9059cbb", // SSTORE (55) + Transfer sig
			wantFlags:    []string{},             // Should NOT have Stateless or FakeToken
			wantScoreMin: 0,
		},
		{
			name:         "MintableBurnable",
			bytecode:     "40c10f1942966c6855", // Mint sig + Burn sig + SSTORE
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
			bytecode:     "a9059cbb0455", // Transfer sig + DIV (04) + SSTORE
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
			wantFlags:    []string{"UncheckedCall"},
			wantScoreMin: 25, // LowLevelCall (10) + UncheckedCall (15)
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
			bytecode:     "673448dd55", // constructor() sig + SSTORE
			wantFlags:    []string{"IncorrectConstructor"},
			wantScoreMin: 5,
		},
		{
			name:         "PotentialHoneypot",
			bytecode:     "a9059cbb55", // Transfer sig + SSTORE + NO Transfer Event Topic
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
			bytecode:     "6000551820a4b7618bde71dce8cdc73aab6c95905fad24", // SSTORE + ERC1820 Address
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
			bytecode:     "3ccfd60b715018a655", // withdraw() + renounceOwnership() + SSTORE
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
			bytecode:     "6000555265656e7472616e63794775617264", // SSTORE + "ReentrancyGuard" string
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
			bytecode:     "a9059cbb330155", // TransferSig + CALLER (33) + ADD (01) + SSTORE (55) (No MintSig)
			wantFlags:    []string{"HiddenMint"},
			wantScoreMin: 40,
		},
		{
			name:         "GasGriefing_Invalid",
			bytecode:     "fe", // INVALID (0xFE)
			wantFlags:    []string{"GasGriefing"},
			wantScoreMin: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _ := hex.DecodeString(tt.bytecode)
			flags, score := analyzeCode(code)

			for _, want := range tt.wantFlags {
				found := false
				for _, got := range flags {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("analyzeCode() missing flag %v. Got: %v", want, flags)
				}
			}

			if score < tt.wantScoreMin {
				t.Errorf("analyzeCode() score = %v, want >= %v", score, tt.wantScoreMin)
			}
		})
	}
}

func BenchmarkAnalyzeCode(b *testing.B) {
	// Simulate a complex contract bytecode with various opcodes and signatures
	code, _ := hex.DecodeString("60806040526004361061005760003560e01c8063a9059cbb1461005c57806370a0823114610089575b600080fd5b6100876004803603604081101561007257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506100a1565b005b6100876004803603602081101561009f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061012d565b600055565b6000549056")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzeCode(code)
	}
}

func TestWatcher_HandleOwnershipTransfer(t *testing.T) {
	// Setup temporary output file
	tmpFile, err := os.CreateTemp("", "eth-watch-test-ownership-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	f, err := os.OpenFile(tmpFile.Name(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	w := &Watcher{
		tracked: make(map[string]*ContractState),
		promMetrics: WatcherMetrics{
			OwnershipTransfersDetected: prometheus.NewCounter(prometheus.CounterOpts{}),
		},
	}

	contractAddr := "0x1234567890123456789012345678901234567890"
	w.tracked[strings.ToLower(contractAddr)] = &ContractState{
		Deployer:  "0xdeployer",
		TokenType: "ERC20",
	}

	// Test 1: Normal Transfer
	newOwner := "0x9999999999999999999999999999999999999999"
	log1 := types.Log{
		Address: common.HexToAddress(contractAddr),
		Topics: []common.Hash{
			common.HexToHash("0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"), // Sig
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"), // Old
			common.HexToHash(newOwner), // New
		},
		BlockNumber: 100,
		TxHash:      common.HexToHash("0xabc"),
	}

	w.handleOwnershipTransfer(log1, f)

	// Test 2: Renounce (Transfer to Zero)
	log2 := types.Log{
		Address: common.HexToAddress(contractAddr),
		Topics: []common.Hash{
			common.HexToHash("0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"),
			common.HexToHash(newOwner),
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"), // Zero
		},
		BlockNumber: 101,
		TxHash:      common.HexToHash("0xdef"),
	}

	w.handleOwnershipTransfer(log2, f)

	// Verify output
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("Expected 2 lines, got %d", len(lines))
	}

	// Check line 1
	if !strings.Contains(lines[0], "OwnershipTransferred") {
		t.Errorf("Line 1 missing OwnershipTransferred flag: %s", lines[0])
	}
	if strings.Contains(lines[0], "OwnershipRenounced") {
		t.Errorf("Line 1 should not have OwnershipRenounced: %s", lines[0])
	}

	// Check line 2
	if !strings.Contains(lines[1], "OwnershipRenounced") {
		t.Errorf("Line 2 missing OwnershipRenounced flag: %s", lines[1])
	}
}

func TestBuildRPCURL(t *testing.T) {
	tests := []struct {
		name string
		base string
		key  string
		want string
	}{
		{
			name: "NoKey",
			base: "https://rpc.example.com",
			key:  "",
			want: "https://rpc.example.com",
		},
		{
			name: "SimpleAppend",
			base: "https://rpc.example.com",
			key:  "12345",
			want: "https://rpc.example.com/12345",
		},
		{
			name: "BaseWithSlash",
			base: "https://rpc.example.com/",
			key:  "12345",
			want: "https://rpc.example.com/12345",
		},
		{
			name: "QueryParamKey",
			base: "https://rpc.example.com",
			key:  "?key=12345",
			want: "https://rpc.example.com?key=12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildRPCURL(tt.base, tt.key); got != tt.want {
				t.Errorf("buildRPCURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "ValidConfig",
			cfg: Config{
				RPC: []RPCConfig{{URL: "wss://example.com"}},
			},
			wantErr: false,
		},
		{
			name: "NoRPCs",
			cfg: Config{
				RPC: []RPCConfig{},
			},
			wantErr: true,
		},
		{
			name: "EmptyRPCURL",
			cfg: Config{
				RPC: []RPCConfig{{URL: ""}},
			},
			wantErr: true,
		},
		{
			name: "ValidWhaleThreshold",
			cfg: Config{
				RPC:            []RPCConfig{{URL: "wss://example.com"}},
				WhaleThreshold: "1000000000000000000",
			},
			wantErr: false,
		},
		{
			name: "InvalidWhaleThreshold",
			cfg: Config{
				RPC:            []RPCConfig{{URL: "wss://example.com"}},
				WhaleThreshold: "not-a-number",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConfig(&tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
