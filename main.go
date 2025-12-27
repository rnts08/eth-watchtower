package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	maxRPCFailures  = 3
	rpcTripDuration = 5 * time.Minute
)

type Config struct {
	RPC    []string `json:"rpc"`
	APIKey string   `json:"apiKey,omitempty"`
	Output string   `json:"output"`
	Log    string   `json:"log"`

	Events struct {
		Transfers  bool `json:"transfers"`
		Liquidity  bool `json:"liquidity"`
		Trades     bool `json:"trades"`
		FlashLoans bool `json:"flashloans"`
	} `json:"events"`

	Dexes []struct {
		Name             string `json:"name"`
		PairCreatedTopic string `json:"pairCreatedTopic"`
		SwapTopic        string `json:"swapTopic"`
	} `json:"dexes"`

	Contracts []struct {
		Address    string  `json:"address"`
		Name       string  `json:"name"`
		Type       string  `json:"type"`
		RiskWeight float64 `json:"risk_weight"`
	} `json:"contracts"`
}

type Finding struct {
	Contract     string   `json:"contract"`
	Deployer     string   `json:"deployer"`
	Block        uint64   `json:"block"`
	TokenType    string   `json:"tokenType"`
	MintDetected bool     `json:"mintDetected"`
	RiskScore    int      `json:"riskScore"`
	Flags        []string `json:"flags"`
	TxHash       string   `json:"txHash"`
}

type ContractState struct {
	Deployer         string
	TokenType        string
	Mints            int
	LiquidityCreated bool
	Traded           bool
}

type RPCState struct {
	URL          string
	FailureCount int
	TrippedUntil time.Time
	lock         sync.Mutex
}

type WatcherStats struct {
	NewContracts int
	Mints        int
	Liquidity    int
	Trades       int
	FlashLoans   int
}

type WatcherMetrics struct {
	ContractsDiscovered    prometheus.Counter
	MintsDetected          prometheus.Counter
	LiquidityEvents        prometheus.Counter
	TradesDetected         prometheus.Counter
	FlashLoansDetected     prometheus.Counter
	RPCStalled             prometheus.Gauge
	ActiveRPC              *prometheus.GaugeVec
	RPCLatency             prometheus.Histogram
	RPCCircuitBreakerTrips *prometheus.CounterVec
	CodeAnalysisFlags      *prometheus.CounterVec
}

type Watcher struct {
	cfg            Config
	tracked        map[string]*ContractState
	lock           sync.RWMutex
	transferSig    common.Hash
	dexPairs       []common.Hash
	dexSwaps       []common.Hash
	flashLoanSig   common.Hash
	startTime      time.Time
	stats          WatcherStats
	promMetrics    WatcherMetrics
	lastHeaderTime time.Time
	rpcStates      []*RPCState
}

func main() {
	w := &Watcher{
		tracked:        make(map[string]*ContractState),
		startTime:      time.Now(),
		lastHeaderTime: time.Now(),
	}

	configPath := flag.String("config", "config.json", "Path to configuration JSON")
	metricsAddr := flag.String("metrics", ":2112", "Address to serve Prometheus metrics")
	flag.Parse()

	w.loadConfig(*configPath)
	w.setupLogging()

	w.rpcStates = make([]*RPCState, len(w.cfg.RPC))
	for i, rpcURL := range w.cfg.RPC {
		w.rpcStates[i] = &RPCState{URL: rpcURL}
	}

	w.promMetrics = WatcherMetrics{
		ContractsDiscovered: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_contracts_discovered_total",
			Help: "Total number of new contracts discovered",
		}),
		MintsDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_mints_detected_total",
			Help: "Total number of mints detected",
		}),
		LiquidityEvents: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_liquidity_events_total",
			Help: "Total number of liquidity events detected",
		}),
		TradesDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_trades_detected_total",
			Help: "Total number of trades detected",
		}),
		FlashLoansDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_flashloans_detected_total",
			Help: "Total number of flashloans detected",
		}),
		RPCStalled: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "eth_watcher_rpc_stalled",
			Help: "Indicates if the RPC connection is stalled (1=stalled, 0=healthy)",
		}),
		ActiveRPC: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "eth_watcher_active_rpc",
			Help: "Indicates which RPC endpoint is currently active (1=active, 0=inactive)",
		}, []string{"url"}),
		RPCLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "eth_watcher_rpc_latency_seconds",
			Help:    "RPC connection latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		RPCCircuitBreakerTrips: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eth_watcher_rpc_circuit_breaker_trips_total",
			Help: "Total number of times the RPC circuit breaker has been tripped per endpoint",
		}, []string{"url"}),
		CodeAnalysisFlags: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eth_watcher_code_analysis_flags_total",
			Help: "Total number of times a specific code analysis flag has been detected",
		}, []string{"flag"}),
	}
	prometheus.MustRegister(w.promMetrics.ContractsDiscovered, w.promMetrics.MintsDetected, w.promMetrics.LiquidityEvents, w.promMetrics.TradesDetected, w.promMetrics.FlashLoansDetected, w.promMetrics.RPCStalled, w.promMetrics.ActiveRPC, w.promMetrics.RPCLatency, w.promMetrics.RPCCircuitBreakerTrips, w.promMetrics.CodeAnalysisFlags)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("Metrics server listening on %s", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	log.Println("eth-watch starting…")

	outFile, err := os.OpenFile(w.cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer outFile.Close()

	// Keccak-256 hash of the standard ERC-20 and ERC-721 Transfer event signature.
	w.transferSig = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

	// Keccak-256 hash of Aave V2 FlashLoan event: FlashLoan(address,address,address,uint256,uint256,uint16)
	w.flashLoanSig = common.HexToHash("0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac")

	for _, d := range w.cfg.Dexes {
		w.dexPairs = append(w.dexPairs, common.HexToHash(d.PairCreatedTopic))
		w.dexSwaps = append(w.dexSwaps, common.HexToHash(d.SwapTopic))
	}

	w.loadWatchedContracts()

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutdown signal received, stopping...")
		rootCancel()
	}()

	rpcIndex := 0
	for {
		if rootCtx.Err() != nil {
			break
		}

		var client *ethclient.Client
		var err error

		// Attempt to connect, rotating through RPCs and respecting circuit breakers.
		// We loop through all available RPCs once per connection attempt cycle.
		for i := 0; i < len(w.rpcStates); i++ {
			rpcState := w.rpcStates[rpcIndex]

			rpcState.lock.Lock()
			isTripped := time.Now().Before(rpcState.TrippedUntil)
			rpcState.lock.Unlock()

			if isTripped {
				rpcIndex = (rpcIndex + 1) % len(w.rpcStates)
				continue // Circuit is open, skip this RPC.
			}

			url := rpcState.URL
			client, err = ethclient.Dial(url)
			if err == nil {
				log.Printf("Connected to RPC: %s", url)
				// Reset failure count on successful connection
				rpcState.lock.Lock()
				rpcState.FailureCount = 0
				rpcState.lock.Unlock()

				for _, r := range w.cfg.RPC {
					w.promMetrics.ActiveRPC.WithLabelValues(r).Set(0)
				}
				w.promMetrics.ActiveRPC.WithLabelValues(url).Set(1)
				break
			}

			// Connection failed
			log.Printf("RPC connection failed to %s: %v. Trying next...", url, err)
			rpcState.lock.Lock()
			rpcState.FailureCount++
			if rpcState.FailureCount >= maxRPCFailures {
				rpcState.TrippedUntil = time.Now().Add(rpcTripDuration)
				log.Printf("Circuit breaker tripped for %s for %v", url, rpcTripDuration)
				w.promMetrics.RPCCircuitBreakerTrips.WithLabelValues(url).Inc()
			}
			rpcState.lock.Unlock()

			rpcIndex = (rpcIndex + 1) % len(w.rpcStates)
		}

		if client == nil {
			log.Printf("All RPC connections failed. Retrying in 5s...")
			select {
			case <-rootCtx.Done():
				continue
			case <-time.After(5 * time.Second):
				continue
			}
		}

		sessCtx, sessCancel := context.WithCancel(rootCtx)
		var wg sync.WaitGroup

		wg.Add(1)
		go w.startWatchdog(sessCtx, client, &wg, sessCancel)

		wg.Add(1)
		go w.subscribeDeployments(sessCtx, client, outFile, &wg, sessCancel)

		if w.cfg.Events.Transfers {
			wg.Add(1)
			go w.subscribeTransfers(sessCtx, client, outFile, &wg, sessCancel)
		}
		if w.cfg.Events.Liquidity || w.cfg.Events.Trades {
			wg.Add(1)
			go w.subscribeLiquidityAndTrades(sessCtx, client, outFile, &wg, sessCancel)
		}
		if w.cfg.Events.FlashLoans {
			wg.Add(1)
			go w.subscribeFlashLoans(sessCtx, client, outFile, &wg, sessCancel)
		}

		<-sessCtx.Done()
		client.Close()
		wg.Wait()
		log.Println("Session ended, reconnecting...")

		// Rotate to the next RPC for the next session attempt
		rpcIndex = (rpcIndex + 1) % len(w.cfg.RPC)
	}
	log.Println("Graceful shutdown complete")
}

func (w *Watcher) loadConfig(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("config open error: %v", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&w.cfg); err != nil {
		log.Fatalf("config decode error: %v", err)
	}

	if len(w.cfg.RPC) == 0 {
		log.Fatal("rpc list required in config")
	}
	if w.cfg.Output == "" {
		w.cfg.Output = "eth-watch-events.jsonl"
	}
	if w.cfg.Log == "" {
		w.cfg.Log = "eth-watch.log"
	}
}

func (w *Watcher) setupLogging() {
	logFile, err := os.OpenFile(w.cfg.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("log file open error: %v", err)
	}
	log.SetOutput(logFile)
}

func (w *Watcher) loadWatchedContracts() {
	for _, c := range w.cfg.Contracts {
		addr := strings.ToLower(c.Address)
		w.tracked[addr] = &ContractState{
			Deployer:  "unknown",
			TokenType: c.Type,
		}
	}
	log.Printf("Loaded %d watched contracts\n", len(w.tracked))
}

func (w *Watcher) startWatchdog(ctx context.Context, client *ethclient.Client, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Measure latency
			start := time.Now()
			_, err := client.BlockNumber(ctx)
			if err == nil {
				w.promMetrics.RPCLatency.Observe(time.Since(start).Seconds())
			}

			w.lock.RLock()
			last := w.lastHeaderTime
			w.lock.RUnlock()

			if time.Since(last) > 60*time.Second {
				log.Printf("ALERT: RPC connection stalled! No new blocks seen for %v. Reconnecting...", time.Since(last).Round(time.Second))
				w.promMetrics.RPCStalled.Set(1)
				cancel()
				return
			} else {
				w.promMetrics.RPCStalled.Set(0)
			}
		}
	}
}

func (w *Watcher) subscribeDeployments(ctx context.Context, client *ethclient.Client, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()

	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(ctx, headers)
	if err != nil {
		log.Printf("Header subscription failed: %v", err)
		cancel()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sub.Err():
			log.Printf("Header subscription error: %v", err)
			cancel()
			return

		case header := <-headers:
			w.lock.Lock()
			w.lastHeaderTime = time.Now()
			w.lock.Unlock()

			block, err := client.BlockByHash(context.Background(), header.Hash())
			if err != nil {
				log.Printf("Block lookup error: %v", err)
				continue
			}

			for _, tx := range block.Transactions() {
				if tx.To() != nil {
					continue
				}

				receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
				if err != nil || receipt.ContractAddress == (common.Address{}) {
					continue
				}

				code, err := client.CodeAt(context.Background(), receipt.ContractAddress, nil)
				if err != nil || len(code) == 0 {
					continue
				}

				tokenType := detectTokenType(code)
				if tokenType == "" {
					continue
				}

				from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
				if err != nil {
					continue
				}

				addr := strings.ToLower(receipt.ContractAddress.Hex())

				w.lock.Lock()
				w.tracked[addr] = &ContractState{
					Deployer:  from.Hex(),
					TokenType: tokenType,
				}
				w.stats.NewContracts++
				w.promMetrics.ContractsDiscovered.Inc()
				w.lock.Unlock()

				log.Printf("New contract %s type=%s deployer=%s", addr, tokenType, from.Hex())

				analysisFlags, analysisScore := analyzeCode(code)
				for _, flag := range analysisFlags {
					w.promMetrics.CodeAnalysisFlags.WithLabelValues(flag).Inc()
				}
				flags := []string{"NewContract"}
				flags = append(flags, analysisFlags...)

				writeEvent(out, Finding{
					Contract:  addr,
					Deployer:  from.Hex(),
					Block:     receipt.BlockNumber.Uint64(),
					TokenType: tokenType,
					RiskScore: 10 + analysisScore,
					Flags:     flags,
					TxHash:    tx.Hash().Hex(),
				})

				w.writeStats()
			}
		}
	}
}

func (w *Watcher) subscribeTransfers(ctx context.Context, client *ethclient.Client, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()

	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{{w.transferSig}},
	}

	logsChan := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(ctx, query, logsChan)
	if err != nil {
		log.Printf("Transfer subscription failed: %v", err)
		cancel()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sub.Err():
			log.Printf("Transfer subscription error: %v", err)
			cancel()
			return

		case vLog := <-logsChan:
			w.handleTransfer(vLog, out)
		}
	}
}

func (w *Watcher) subscribeLiquidityAndTrades(ctx context.Context, client *ethclient.Client, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()

	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{append(w.dexPairs, w.dexSwaps...)},
	}

	logsChan := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(ctx, query, logsChan)
	if err != nil {
		log.Printf("Liquidity subscription failed: %v", err)
		cancel()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sub.Err():
			log.Printf("Liquidity subscription error: %v", err)
			cancel()
			return

		case vLog := <-logsChan:
			w.handleLiquidityOrTrade(vLog, out)
		}
	}
}

func (w *Watcher) subscribeFlashLoans(ctx context.Context, client *ethclient.Client, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()

	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{{w.flashLoanSig}},
	}

	logsChan := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(ctx, query, logsChan)
	if err != nil {
		log.Printf("FlashLoan subscription failed: %v", err)
		cancel()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sub.Err():
			log.Printf("FlashLoan subscription error: %v", err)
			cancel()
			return

		case vLog := <-logsChan:
			w.handleFlashLoan(vLog, out)
		}
	}
}

func (w *Watcher) handleTransfer(vLog types.Log, out *os.File) {
	if len(vLog.Topics) < 3 {
		return
	}

	from := common.HexToAddress(vLog.Topics[1].Hex())
	if from != (common.Address{}) {
		return
	}

	contract := strings.ToLower(vLog.Address.Hex())

	w.lock.Lock()
	state, ok := w.tracked[contract]
	if !ok {
		w.lock.Unlock()
		return
	}
	state.Mints++
	w.stats.Mints++
	w.promMetrics.MintsDetected.Inc()
	w.lock.Unlock()

	log.Printf("Mint detected contract=%s totalMints=%d", contract, state.Mints)

	flags := []string{"MintDetected"}
	score := 40 + state.Mints*15

	to := common.HexToAddress(vLog.Topics[2].Hex())
	if to.Hex() == state.Deployer {
		flags = append(flags, "MintToDeployer")
		score += 15
	}

	if state.Mints > 1 {
		flags = append(flags, "MultipleMints")
	}

	if score > 100 {
		score = 100
	}

	writeEvent(out, Finding{
		Contract:     contract,
		Deployer:     state.Deployer,
		Block:        uint64(vLog.BlockNumber),
		TokenType:    state.TokenType,
		MintDetected: true,
		RiskScore:    score,
		Flags:        flags,
		TxHash:       vLog.TxHash.Hex(),
	})

	w.writeStats()
}

func (w *Watcher) handleLiquidityOrTrade(vLog types.Log, out *os.File) {
	if containsHash(w.dexPairs, vLog.Topics[0]) {
		w.handleLiquidityEvent(vLog, out)
		return
	}

	if containsHash(w.dexSwaps, vLog.Topics[0]) {
		w.handleTradeEvent(vLog, out)
	}
}

func (w *Watcher) handleLiquidityEvent(vLog types.Log, out *os.File) {
	if len(vLog.Topics) < 3 {
		return
	}

	// Extract token addresses from topics (Topic 1 and Topic 2)
	token0 := common.HexToAddress(vLog.Topics[1].Hex())
	token1 := common.HexToAddress(vLog.Topics[2].Hex())
	tokens := []string{strings.ToLower(token0.Hex()), strings.ToLower(token1.Hex())}

	var findings []Finding

	w.lock.Lock()
	for _, addr := range tokens {
		state, ok := w.tracked[addr]
		if !ok || state.LiquidityCreated {
			continue
		}

		state.LiquidityCreated = true
		w.stats.Liquidity++
		w.promMetrics.LiquidityEvents.Inc()

		findings = append(findings, Finding{
			Contract:  addr,
			Deployer:  state.Deployer,
			Block:     uint64(vLog.BlockNumber),
			TokenType: state.TokenType,
			RiskScore: 25,
			Flags:     []string{"LiquidityCreated"},
			TxHash:    vLog.TxHash.Hex(),
		})
	}
	w.lock.Unlock()

	for _, f := range findings {
		log.Printf("Liquidity detected for %s", f.Contract)
		writeEvent(out, f)
		w.writeStats()
	}
}

func (w *Watcher) handleTradeEvent(vLog types.Log, out *os.File) {
	addr := strings.ToLower(vLog.Address.Hex())

	w.lock.Lock()
	state, ok := w.tracked[addr]
	if !ok || state.Traded {
		w.lock.Unlock()
		return
	}

	state.Traded = true
	w.stats.Trades++
	w.promMetrics.TradesDetected.Inc()

	f := Finding{
		Contract:  addr,
		Deployer:  state.Deployer,
		Block:     uint64(vLog.BlockNumber),
		TokenType: state.TokenType,
		RiskScore: 20,
		Flags:     []string{"TradingDetected"},
		TxHash:    vLog.TxHash.Hex(),
	}
	w.lock.Unlock()

	log.Printf("Trade detected for %s", addr)
	writeEvent(out, f)
	w.writeStats()
}

func (w *Watcher) handleFlashLoan(vLog types.Log, out *os.File) {
	addr := strings.ToLower(vLog.Address.Hex())

	w.lock.Lock()
	state, ok := w.tracked[addr]
	if !ok {
		w.lock.Unlock()
		return
	}

	w.stats.FlashLoans++
	w.promMetrics.FlashLoansDetected.Inc()
	w.lock.Unlock()

	log.Printf("FlashLoan detected on %s", addr)

	// Extract asset address from Topic 3 (indexed asset)
	var asset string
	if len(vLog.Topics) >= 4 {
		asset = common.HexToAddress(vLog.Topics[3].Hex()).Hex()
	}

	flags := []string{"FlashLoanDetected"}
	if asset != "" {
		flags = append(flags, "Asset:"+asset)
	}

	writeEvent(out, Finding{
		Contract:  addr,
		Deployer:  state.Deployer,
		Block:     uint64(vLog.BlockNumber),
		TokenType: state.TokenType,
		RiskScore: 50,
		Flags:     flags,
		TxHash:    vLog.TxHash.Hex(),
	})
	w.writeStats()
}

func detectTokenType(code []byte) string {
	s := strings.ToLower(common.Bytes2Hex(code))
	switch {
	case strings.Contains(s, "a9059cbb"):
		return "ERC20"
	case strings.Contains(s, "80ac58cd"):
		return "ERC721"
	case strings.Contains(s, "d9b67a26"):
		return "ERC1155"
	default:
		return ""
	}
}

func analyzeCode(code []byte) ([]string, int) {
	var flags []string
	score := 0
	hexCode := common.Bytes2Hex(code)

	// Check for common function selectors (signatures)
	// mint(address,uint256): 40c10f19
	if strings.Contains(hexCode, "40c10f19") {
		flags = append(flags, "Mintable")
		score += 10
	}
	// burn(uint256): 42966c68
	if strings.Contains(hexCode, "42966c68") {
		flags = append(flags, "Burnable")
	}
	// transferOwnership(address): f2fde38b
	if strings.Contains(hexCode, "f2fde38b") {
		flags = append(flags, "Ownable")
	}
	// blacklist(address): 1d3b9edf, isBlacklisted(address): fe575a87
	if strings.Contains(hexCode, "1d3b9edf") || strings.Contains(hexCode, "fe575a87") {
		flags = append(flags, "Blacklist")
		score += 20
	}
	// upgradeTo(address): 3659cfe6
	if strings.Contains(hexCode, "3659cfe6") {
		flags = append(flags, "Upgradable")
		score += 5
	}
	// supportsInterface(bytes4): 01ffc9a7
	if strings.Contains(hexCode, "01ffc9a7") {
		flags = append(flags, "InterfaceCheck")
	}
	// constructor(): 673448dd (Incorrect naming in modern Solidity)
	if strings.Contains(hexCode, "673448dd") {
		flags = append(flags, "IncorrectConstructor")
		score += 5
	}
	// withdraw(): 3ccfd60b, withdraw(uint256): 2e1a7d4d
	if strings.Contains(hexCode, "3ccfd60b") || strings.Contains(hexCode, "2e1a7d4d") {
		flags = append(flags, "Withdrawal")
	}
	// renounceOwnership(): 715018a6
	if strings.Contains(hexCode, "715018a6") {
		flags = append(flags, "RenounceOwnership")
	}
	// flashLoan(...): 5cffe9de (Aave/Standard)
	if strings.Contains(hexCode, "5cffe9de") {
		flags = append(flags, "FlashLoan")
	}
	// transfer(address,uint256): a9059cbb (Used for FakeToken detection)
	hasTransferSig := strings.Contains(hexCode, "a9059cbb")

	// Opcode scanning
	hasSelfDestruct := false
	hasDelegateCall := false
	hasTimestamp := false
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

	hasAddSubMul := false
	hasCalldataLoad := false
	hasPanic := strings.Contains(hexCode, "4e487b71")
	hasReentrancyGuard := strings.Contains(hexCode, "5265656e7472616e63794775617264") // "ReentrancyGuard"

	// Counters for loop analysis
	countCalls := 0
	countDelegateCalls := 0
	countCreates := 0
	countSelfDestructs := 0
	countGasOps := 0
	countSload := 0
	countSstore := 0
	jumpDests := make(map[int]struct{ c, dc, cr, sd, g, ss int })

	// Transfer Event Topic: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
	hasTransferEvent := strings.Contains(hexCode, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

	// ERC1820 Registry Address (ERC777): 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24
	hasERC1820 := strings.Contains(hexCode, "1820a4b7618bde71dce8cdc73aab6c95905fad24")

	pc := 0
	lastOp := byte(0)
	var lastPushData []byte
	lastDivPC := -1

	for pc < len(code) {
		op := code[pc]

		// Skip PUSH data (PUSH1=0x60 ... PUSH32=0x7F)
		if op >= 0x60 && op <= 0x7F {
			pushBytes := int(op - 0x5F)
			if pc+1+pushBytes <= len(code) {
				lastPushData = code[pc+1 : pc+1+pushBytes]
			} else {
				lastPushData = nil
			}
			lastOp = op
			pc += pushBytes + 1
			continue
		}

		switch op {
		case 0x01, 0x03: // ADD, SUB
			hasAddSubMul = true
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
						flags = append(flags, "LoopDetected")
						score += 5
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
			}
		case 0x38: // CODESIZE
			if !hasCodeSize {
				hasCodeSize = true
				flags = append(flags, "SuspiciousCodeSize")
				score += 5
			}
		case 0x3D: // RETURNDATASIZE
			hasReturnDataSize = true
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
		case 0x50: // POP
			if lastOp == 0x54 { // SLOAD
				hasShadowing = true
			}
		case 0x5A: // GAS
			countGasOps++
			if !hasGas {
				hasGas = true
				flags = append(flags, "GasUsage")
				score += 5
			}
		case 0xFF: // SELFDESTRUCT
			countSelfDestructs++
			if !hasSelfDestruct {
				hasSelfDestruct = true
				flags = append(flags, "SelfDestruct")
				score += 50
			}
			if lastOp == 0x73 && !hasHardcodedSelfDestruct { // PUSH20 before SELFDESTRUCT
				hasHardcodedSelfDestruct = true
				flags = append(flags, "HardcodedSelfDestruct")
				score += 50
			}
			canSendEth = true
		case 0xF4: // DELEGATECALL
			countDelegateCalls++
			if !hasDelegateCall {
				hasDelegateCall = true
				flags = append(flags, "DelegateCall")
				score += 20
			}
			// Check for DelegateCall to Zero (PUSH0 or PUSH1 0x00 before DELEGATECALL)
			if lastOp == 0x5F || (lastOp == 0x60 && len(lastPushData) == 1 && lastPushData[0] == 0) {
				if !hasDelegateCallToZero {
					hasDelegateCallToZero = true
					flags = append(flags, "DelegateCallToZero")
					score += 30
				}
			}
			canSendEth = true
		case 0x42: // TIMESTAMP
			if !hasTimestamp {
				hasTimestamp = true
				flags = append(flags, "Timestamp")
				score += 5
			}
		case 0x32: // ORIGIN
			if !hasOrigin {
				hasOrigin = true
				flags = append(flags, "TxOrigin")
				score += 10
			}
		case 0x55: // SSTORE
			hasSstore = true
			countSstore++
			if lastOp == 0x60 && len(lastPushData) == 1 && lastPushData[0] == 0 {
				if !hasWriteToSlotZero {
					hasWriteToSlotZero = true
					flags = append(flags, "WriteToSlotZero")
					score += 20
				}
			}
		case 0x3A: // GASPRICE
			if !hasGasPrice {
				hasGasPrice = true
				flags = append(flags, "GasPriceCheck")
				score += 5
			}
		case 0x3B: // EXTCODESIZE
			if !hasExtCodeSize {
				hasExtCodeSize = true
				flags = append(flags, "AntiContractCheck")
				score += 10
			}
		case 0x3F: // EXTCODEHASH
			if !hasExtCodeHash {
				hasExtCodeHash = true
				flags = append(flags, "CodeHashCheck")
				score += 10
			}
		case 0x41: // COINBASE
			if !hasCoinbase {
				hasCoinbase = true
				flags = append(flags, "CoinbaseCheck")
				score += 5
			}
		case 0x43: // NUMBER
			if !hasBlockNumber {
				hasBlockNumber = true
				flags = append(flags, "BlockNumberCheck")
				score += 5
			}
		case 0x44: // DIFFICULTY (PREVRANDAO)
			if !hasDifficulty {
				hasDifficulty = true
				flags = append(flags, "WeakRandomness")
				score += 10
			}
		case 0x45: // GASLIMIT
			if !hasGasLimit {
				hasGasLimit = true
				flags = append(flags, "BlockStuffing")
				score += 5
			}
		case 0x46: // CHAINID
			if !hasChainID {
				hasChainID = true
				flags = append(flags, "ChainIDCheck")
				score += 5
			}
		case 0x47: // SELFBALANCE
			if !hasSelfBalance {
				hasSelfBalance = true
				flags = append(flags, "CheckOwnBalance")
				score += 5
			}
		case 0xF5: // CREATE2
			if !hasCreate2 {
				hasCreate2 = true
				flags = append(flags, "Metamorphic")
				score += 30
			}
			countCreates++
			canSendEth = true
		case 0x40: // BLOCKHASH
			if !hasBlockHash {
				hasBlockHash = true
				flags = append(flags, "BadRandomness")
				score += 15
			}
		case 0x36: // CALLDATASIZE
			if !hasCalldataSize {
				hasCalldataSize = true
				flags = append(flags, "CalldataSizeCheck")
				score += 5
			}
		case 0xF0: // CREATE
			countCreates++
			if !hasCreate {
				hasCreate = true
				flags = append(flags, "ContractFactory")
				score += 10
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
					flags = append(flags, "HardcodedGasLimit")
					score += 5
				}
			}
			if !hasLowLevelCall {
				hasLowLevelCall = true
				flags = append(flags, "LowLevelCall")
				score += 10
			}
			canSendEth = true
		case 0xFD: // REVERT
			hasRevert = true
		case 0xF3: // RETURN
			hasReturn = true
		case 0x00: // STOP
			hasStop = true
		}
		lastOp = op
		pc++
	}

	if !hasSstore {
		flags = append(flags, "Stateless")
		score += 30

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
			flags = append(flags, "FakeToken")
			score += 50
		}
	}

	if hasTransferSig && hasDiv {
		flags = append(flags, "TaxToken")
		score += 20
	}
	if hasStrictBalance {
		flags = append(flags, "StrictBalanceEquality")
		score += 10
	}
	if hasUncheckedCall {
		flags = append(flags, "UncheckedCall")
		score += 15
	}
	if !canSendEth {
		flags = append(flags, "LockedEther")
		score += 5
	}
	if hasDivBeforeMul {
		flags = append(flags, "DivideBeforeMultiply")
		score += 10
	}
	if hasShadowing {
		flags = append(flags, "ShadowingState")
		score += 5
	}
	if hasSstore && hasTransferSig && !hasTransferEvent {
		flags = append(flags, "HiddenMint")
		score += 40
	}
	if hasRevert && !hasReturn && !hasStop && !hasSelfDestruct {
		flags = append(flags, "ReturnBomb")
		score += 50
	}
	if hasERC1820 {
		flags = append(flags, "ERC777Reentrancy")
		score += 20
	}
	if hasLowLevelCall && !hasReturnDataSize {
		flags = append(flags, "UncheckedReturnData")
		score += 10
	}
	if hasInfiniteLoop {
		flags = append(flags, "InfiniteLoop")
		score += 20
	}
	if hasCallInLoop {
		flags = append(flags, "CallInLoop")
		score += 10
	}
	if hasDelegateCallInLoop {
		flags = append(flags, "DelegateCallInLoop")
		score += 20
	}
	if hasFactoryInLoop {
		flags = append(flags, "FactoryInLoop")
		score += 15
	}
	if hasSelfDestructInLoop {
		flags = append(flags, "SelfDestructInLoop")
		score += 50
	}
	if hasGasDependentLoop {
		flags = append(flags, "GasDependentLoop")
		score += 10
	}
	if countSstore > 0 && countSload == 0 {
		flags = append(flags, "SuspiciousStateChange")
		score += 10
	}
	if hasSstoreInLoop {
		flags = append(flags, "CostlyLoop")
		score += 10
	}
	if hasDelegateCall && hasSelfDestruct {
		flags = append(flags, "ProxyDestruction")
		score += 20
	}
	if hasCreate2 && hasSelfDestruct {
		flags = append(flags, "MetamorphicExploit")
		score += 20
	}
	if hasAddSubMul && !hasPanic {
		flags = append(flags, "UncheckedMath")
		score += 10
	}
	if hasDelegateCall && hasCalldataLoad {
		flags = append(flags, "UnsafeDelegateCall")
		score += 20
	}
	if hasReentrancyGuard {
		flags = append(flags, "ReentrancyGuard")
	}

	return flags, score
}

func bytesToInt(b []byte) int {
	res := 0
	for _, v := range b {
		res = (res << 8) | int(v)
	}
	return res
}

func containsHash(list []common.Hash, h common.Hash) bool {
	for _, v := range list {
		if v == h {
			return true
		}
	}
	return false
}

func writeEvent(out *os.File, f Finding) {
	w := bufio.NewWriter(out)
	b, err := json.Marshal(f)
	if err != nil {
		log.Printf("json marshal error: %v", err)
		return
	}
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
	_ = w.Flush()
}

func (w *Watcher) writeStats() {
	w.lock.RLock()
	defer w.lock.RUnlock()

	uptime := time.Since(w.startTime).Round(time.Second)
	log.Printf(
		"stats uptime=%s contracts=%d mints=%d liquidity=%d trades=%d flashloans=%d",
		uptime,
		w.stats.NewContracts,
		w.stats.Mints,
		w.stats.Liquidity,
		w.stats.Trades,
		w.stats.FlashLoans,
	)
}
