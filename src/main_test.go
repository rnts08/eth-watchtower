package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"eth-watch/metrics"
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
		{"Mixed_ERC20_ERC721", "608060405280ac58cda9059cbb", "ERC20"},    // ERC20 takes precedence
		{"Mixed_ERC721_ERC1155", "608060405280ac58cdd9b67a26", "ERC721"}, // ERC721 takes precedence over ERC1155
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

func BenchmarkWatcher_HandleTransfer(b *testing.B) {
	// Silence logging for benchmark
	log.SetOutput(io.Discard)

	// Setup temporary output file
	tmpFile, err := os.CreateTemp("", "eth-watch-bench-*.jsonl")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	w := &Watcher{
		tracked:     make(map[common.Address]*ContractState),
		promMetrics: metrics.NewWatcherMetrics(),
	}

	contractAddr := "0x1234567890123456789012345678901234567890"
	w.tracked[common.HexToAddress(contractAddr)] = &ContractState{
		Deployer:  common.Address{},
		TokenType: "ERC20",
	}

	vLog := types.Log{
		Address: common.HexToAddress(contractAddr),
		Topics: []common.Hash{
			common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"), // TransferSig
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"), // From Zero
			common.HexToHash("0xreceiver"),
		},
		Data:        common.BigToHash(big.NewInt(1000)).Bytes(),
		BlockNumber: 100,
		TxHash:      common.HexToHash("0xabc"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.handleTransfer(vLog, tmpFile)
	}
}

func TestWatcher_LargeApprovalFlag(t *testing.T) {
	// Setup temporary output file
	tmpFile, err := os.CreateTemp("", "eth-watch-test-approval-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	f, err := os.OpenFile(tmpFile.Name(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// Setup Watcher with global threshold
	threshold := new(big.Int).SetInt64(1000)
	w := &Watcher{
		tracked:        make(map[common.Address]*ContractState),
		whaleThreshold: threshold,
		promMetrics:    metrics.NewWatcherMetrics(),
	}

	contractAddr := "0x1234567890123456789012345678901234567890"
	w.tracked[common.HexToAddress(contractAddr)] = &ContractState{
		Deployer:  common.Address{},
		TokenType: "ERC20",
	}

	// Test: Approval exceeding threshold
	log1 := types.Log{
		Address: common.HexToAddress(contractAddr),
		Topics: []common.Hash{
			common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"), // ApprovalSig
			common.HexToHash("0xowner"),
			common.HexToHash("0xspender"),
		},
		Data:        common.BigToHash(big.NewInt(1500)).Bytes(), // Value > 1000
		BlockNumber: 100,
		TxHash:      common.HexToHash("0xabc"),
	}

	w.handleApproval(log1, f)

	// Verify output
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("Expected 1 line, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "LargeApproval") {
		t.Errorf("Line missing LargeApproval flag: %s", lines[0])
	}
}

func TestWatcher_InfiniteApprovalFlag(t *testing.T) {
	// Setup temporary output file
	tmpFile, err := os.CreateTemp("", "eth-watch-test-inf-approval-*.jsonl")
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
		tracked:     make(map[common.Address]*ContractState),
		promMetrics: metrics.NewWatcherMetrics(),
	}

	contractAddr := "0x1234567890123456789012345678901234567890"
	w.tracked[common.HexToAddress(contractAddr)] = &ContractState{
		Deployer:  common.Address{},
		TokenType: "ERC20",
	}

	// Max Uint256
	maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	// Test: Infinite Approval
	log1 := types.Log{
		Address: common.HexToAddress(contractAddr),
		Topics: []common.Hash{
			common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"), // ApprovalSig
			common.HexToHash("0xowner"),
			common.HexToHash("0xspender"),
		},
		Data:        common.BigToHash(maxUint256).Bytes(),
		BlockNumber: 100,
		TxHash:      common.HexToHash("0xabc"),
	}

	w.handleApproval(log1, f)

	// Verify output
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("Expected 1 line, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "InfiniteApproval") {
		t.Errorf("Line missing InfiniteApproval flag: %s", lines[0])
	}
}

func TestWatcher_ActiveSubscriptionsMetric(t *testing.T) {
	// Setup Watcher
	w := &Watcher{
		promMetrics: metrics.NewWatcherMetrics(),
		cfg: Config{
			Concurrency: 1,
		},
	}

	mockSub := &MockSubscription{errChan: make(chan error)}
	client := &MockEthClient{
		SubscribeNewHeadFunc: func(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
			return mockSub, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	// Create temp file for output
	tmpFile, _ := os.CreateTemp("", "dummy")
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	go w.subscribeDeployments(ctx, client, tmpFile, &wg, func() {})

	// Allow goroutine to start and increment
	time.Sleep(50 * time.Millisecond)

	if val := testutil.ToFloat64(w.promMetrics.ActiveSubscriptions); val != 1 {
		t.Errorf("Expected ActiveSubscriptions to be 1, got %v", val)
	}

	cancel()
	wg.Wait()

	if val := testutil.ToFloat64(w.promMetrics.ActiveSubscriptions); val != 0 {
		t.Errorf("Expected ActiveSubscriptions to be 0, got %v", val)
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
		tracked:    make(map[common.Address]*ContractState),
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

func TestWatcher_CodeAnalysisFlagsMetric(t *testing.T) {
	// Setup Watcher
	w := &Watcher{
		promMetrics: metrics.NewWatcherMetrics(),
		cfg: Config{
			Concurrency:      1,
			AnalyzerPoolSize: 1,
		},
		tracked: make(map[common.Address]*ContractState),
		chainID: big.NewInt(1),
	}
	w.analyzerPool = &sync.Pool{
		New: func() interface{} { return NewAnalyzer(nil) },
	}

	// Mock Client
	mockSub := &MockSubscription{errChan: make(chan error)}
	client := &MockEthClient{
		SubscribeNewHeadFunc: func(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
			go func() {
				ch <- &types.Header{Number: big.NewInt(100), Time: uint64(time.Now().Unix())}
			}()
			return mockSub, nil
		},
		BlockByHashFunc: func(ctx context.Context, hash common.Hash) (*types.Block, error) {
			// Create a signed transaction (contract creation)
			key, _ := crypto.GenerateKey()
			signer := types.LatestSignerForChainID(w.chainID)
			tx, _ := types.SignTx(types.NewContractCreation(0, big.NewInt(0), 100000, big.NewInt(0), nil), signer, key)
			return types.NewBlockWithHeader(&types.Header{Number: big.NewInt(100)}).WithBody(types.Body{Transactions: []*types.Transaction{tx}}), nil
		},
		TransactionReceiptFunc: func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			return &types.Receipt{
				ContractAddress: common.HexToAddress("0x123"),
				BlockNumber:     big.NewInt(100),
			}, nil
		},
		CodeAtFunc: func(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
			// Bytecode: SELFDESTRUCT (ff) + ERC20 signature (a9059cbb) to pass token detection
			return []byte{0xff, 0xa9, 0x05, 0x9c, 0xbb}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	tmpFile, _ := os.CreateTemp("", "dummy")
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	go w.subscribeDeployments(ctx, client, tmpFile, &wg, func() {})

	// Poll for metric update
	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	found := false
	for !found {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for CodeAnalysisFlags metric")
		case <-ticker.C:
			if testutil.ToFloat64(w.promMetrics.CodeAnalysisFlags.WithLabelValues("SelfDestruct")) == 1 {
				found = true
			}
		}
	}

	cancel()
	wg.Wait()
}

func TestWatcher_RPCStalledMetric(t *testing.T) {
	w := &Watcher{
		promMetrics:    metrics.NewWatcherMetrics(),
		lastHeaderTime: time.Now().Add(-2 * time.Minute), // Stalled (> 60s)
	}

	client := &MockEthClient{
		BlockNumberFunc: func(ctx context.Context) (uint64, error) {
			return 100, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	// Run watchdog with very short interval
	go w.startWatchdog(ctx, client, &wg, cancel, 10*time.Millisecond)

	// Wait for cancellation (which happens when stalled)
	select {
	case <-ctx.Done():
		// Success: context cancelled
		if val := testutil.ToFloat64(w.promMetrics.RPCStalled); val != 1 {
			t.Errorf("Expected RPCStalled to be 1, got %v", val)
		}
	case <-time.After(1 * time.Second):
		t.Error("Watchdog failed to detect stall and cancel context")
	}

	wg.Wait()
}

func TestWatcher_WhaleTransferFlag(t *testing.T) {
	// Setup temporary output file
	tmpFile, err := os.CreateTemp("", "eth-watch-test-whale-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	f, err := os.OpenFile(tmpFile.Name(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// Setup Watcher with global threshold
	threshold := new(big.Int).SetInt64(1000)
	w := &Watcher{
		tracked:        make(map[common.Address]*ContractState),
		whaleThreshold: threshold,
		promMetrics:    metrics.NewWatcherMetrics(),
	}

	contractAddr := "0x1234567890123456789012345678901234567890"
	w.tracked[common.HexToAddress(contractAddr)] = &ContractState{
		Deployer:  common.Address{},
		TokenType: "ERC20",
	}

	// Test: Transfer exceeding threshold
	log1 := types.Log{
		Address: common.HexToAddress(contractAddr),
		Topics: []common.Hash{
			common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"), // TransferSig
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"), // From Zero (Mint)
			common.HexToHash("0xreceiver"),
		},
		Data:        common.BigToHash(big.NewInt(1500)).Bytes(), // Value > 1000
		BlockNumber: 100,
		TxHash:      common.HexToHash("0xabc"),
	}

	w.handleTransfer(log1, f)

	// Verify output
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("Expected 1 line, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "WhaleTransfer") {
		t.Errorf("Line missing WhaleTransfer flag: %s", lines[0])
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
		tracked:     make(map[common.Address]*ContractState),
		promMetrics: metrics.NewWatcherMetrics(),
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
		tracked:     make(map[common.Address]*ContractState),
		promMetrics: metrics.NewWatcherMetrics(),
	}

	contractAddr := "0x1234567890123456789012345678901234567890"
	w.tracked[common.HexToAddress(contractAddr)] = &ContractState{
		Deployer:  common.Address{},
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
