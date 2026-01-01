package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
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

type RPCConfig struct {
	URL    string `json:"url"`
	APIKey string `json:"apiKey,omitempty"`
}

type Config struct {
	RPC            []RPCConfig `json:"rpc"`
	Output         string      `json:"output"`
	Log            string      `json:"log"`
	WhaleThreshold string      `json:"whale_threshold"`
	Concurrency    int         `json:"concurrency,omitempty"`

	Events struct {
		Transfers          bool `json:"transfers"`
		Liquidity          bool `json:"liquidity"`
		Trades             bool `json:"trades"`
		FlashLoans         bool `json:"flashloans"`
		Approvals          bool `json:"approvals"`
		OwnershipTransfers bool `json:"ownership_transfers"`
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
	NewContracts       int
	Mints              int
	Liquidity          int
	Trades             int
	FlashLoans         int
	Approvals          int
	OwnershipTransfers int
}

type WatcherMetrics struct {
	ContractsDiscovered        prometheus.Counter
	MintsDetected              prometheus.Counter
	LiquidityEvents            prometheus.Counter
	TradesDetected             prometheus.Counter
	FlashLoansDetected         prometheus.Counter
	ApprovalsDetected          prometheus.Counter
	OwnershipTransfersDetected prometheus.Counter
	RPCStalled                 prometheus.Gauge
	ActiveRPC                  *prometheus.GaugeVec
	RPCLatency                 prometheus.Histogram
	RPCCircuitBreakerTrips     *prometheus.CounterVec
	CodeAnalysisFlags          *prometheus.CounterVec
	ChainIDFetchFailures       *prometheus.CounterVec
	CodeAnalysisDuration       prometheus.Histogram
}

type EthClient interface {
	ChainID(ctx context.Context) (*big.Int, error)
	BlockNumber(ctx context.Context) (uint64, error)
	Close()
	SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)
}

type Watcher struct {
	cfg                     Config
	tracked                 map[string]*ContractState
	lock                    sync.RWMutex
	transferSig             common.Hash
	dexPairs                []common.Hash
	dexSwaps                []common.Hash
	flashLoanSig            common.Hash
	approvalSig             common.Hash
	ownershipTransferredSig common.Hash
	startTime               time.Time
	stats                   WatcherStats
	promMetrics             WatcherMetrics
	lastHeaderTime          time.Time
	rpcStates               []*RPCState
	whaleThreshold          *big.Int
	chainID                 *big.Int
	fileLock                sync.Mutex
	configLock              sync.RWMutex
	sessCancel              context.CancelFunc
	configPath              string
	lastConfigModTime       time.Time
	clientFactory           func(url string) (EthClient, error)
}

func main() {
	w := &Watcher{
		tracked:        make(map[string]*ContractState),
		startTime:      time.Now(),
		lastHeaderTime: time.Now(),
		clientFactory: func(url string) (EthClient, error) {
			return ethclient.Dial(url)
		},
	}

	configPath := flag.String("config", "config.json", "Path to configuration JSON")
	metricsAddr := flag.String("metrics", ":2112", "Address to serve Prometheus metrics")
	concurrencyOverride := flag.Int("concurrency", 0, "Override concurrency level (default: use config)")
	testConfig := flag.Bool("t", false, "Test configuration and exit")
	flag.Parse()

	w.configPath = *configPath
	if info, err := os.Stat(w.configPath); err == nil {
		w.lastConfigModTime = info.ModTime()
	}

	if *testConfig {
		cfg, err := loadConfiguration(w.configPath)
		if err != nil {
			fmt.Printf("Configuration error: %v\n", err)
			os.Exit(1)
		}
		if err := validateConfig(cfg); err != nil {
			fmt.Printf("Configuration validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration OK")
		os.Exit(0)
	}

	w.loadConfig(*configPath)
	if *concurrencyOverride > 0 {
		w.cfg.Concurrency = *concurrencyOverride
	}
	w.setupLogging()

	w.rpcStates = make([]*RPCState, len(w.cfg.RPC))
	for i, rpcCfg := range w.cfg.RPC {
		url := buildRPCURL(rpcCfg.URL, rpcCfg.APIKey)
		w.rpcStates[i] = &RPCState{URL: url}
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
		ApprovalsDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_approvals_detected_total",
			Help: "Total number of approval events detected",
		}),
		OwnershipTransfersDetected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_ownership_transfers_detected_total",
			Help: "Total number of ownership transfer events detected",
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
		ChainIDFetchFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "eth_watcher_chain_id_fetch_failures_total",
			Help: "Total number of failed ChainID fetch attempts",
		}, []string{"url"}),
		CodeAnalysisDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "eth_watcher_code_analysis_duration_seconds",
			Help:    "Time taken to analyze contract bytecode in seconds",
			Buckets: prometheus.DefBuckets,
		}),
	}
	prometheus.MustRegister(w.promMetrics.ContractsDiscovered, w.promMetrics.MintsDetected, w.promMetrics.LiquidityEvents, w.promMetrics.TradesDetected, w.promMetrics.FlashLoansDetected, w.promMetrics.ApprovalsDetected, w.promMetrics.OwnershipTransfersDetected, w.promMetrics.RPCStalled, w.promMetrics.ActiveRPC, w.promMetrics.RPCLatency, w.promMetrics.RPCCircuitBreakerTrips, w.promMetrics.CodeAnalysisFlags, w.promMetrics.ChainIDFetchFailures, w.promMetrics.CodeAnalysisDuration)

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
	defer func() {
		if err := outFile.Close(); err != nil {
			log.Printf("Error closing output file: %v", err)
		}
	}()

	// Keccak-256 hash of the standard ERC-20 and ERC-721 Transfer event signature.
	w.transferSig = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

	// Keccak-256 hash of Aave V2 FlashLoan event: FlashLoan(address,address,address,uint256,uint256,uint16)
	w.flashLoanSig = common.HexToHash("0x631042c832b07452973831137f2d73e395028b44b250dedc5abb0ee766e168ac")

	// Keccak-256 hash of ERC20 Approval event: Approval(address,address,uint256)
	w.approvalSig = common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")

	// Keccak-256 hash of OwnershipTransferred(address,address)
	w.ownershipTransferredSig = common.HexToHash("0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0")

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

	go w.watchConfig(rootCtx)

	w.Run(rootCtx)
	log.Println("Graceful shutdown complete")
}

func (w *Watcher) Run(rootCtx context.Context) {
	rpcIndex := 0
	for rootCtx.Err() == nil {

		var client EthClient
		var err error

		// Attempt to connect, rotating through RPCs and respecting circuit breakers.
		// We loop through all available RPCs once per connection attempt cycle.
		w.configLock.RLock()
		numRPCs := len(w.rpcStates)
		w.configLock.RUnlock()

		for i := 0; i < numRPCs; i++ {
			w.configLock.RLock()
			rpcState := w.rpcStates[rpcIndex%len(w.rpcStates)]
			w.configLock.RUnlock()

			rpcState.lock.Lock()
			isTripped := time.Now().Before(rpcState.TrippedUntil)
			rpcState.lock.Unlock()

			if isTripped {
				rpcIndex++
				continue // Circuit is open, skip this RPC.
			}

			url := rpcState.URL
			client, err = w.clientFactory(url)
			if err == nil {
				// Attempt to fetch ChainID with retries
				var cid *big.Int
				for attempt := 0; attempt < 3; attempt++ {
					cid, err = client.ChainID(context.Background())
					if err == nil {
						break
					}
					w.promMetrics.ChainIDFetchFailures.WithLabelValues(url).Inc()
					time.Sleep(1 * time.Second)
				}

				if err == nil {
					w.chainID = cid
					log.Printf("Connected to RPC: %s (ChainID: %s)", url, cid)
					// Reset failure count on successful connection
					rpcState.lock.Lock()
					rpcState.FailureCount = 0
					rpcState.lock.Unlock()

					w.configLock.RLock()
					for _, s := range w.rpcStates {
						w.promMetrics.ActiveRPC.WithLabelValues(s.URL).Set(0)
					}
					w.configLock.RUnlock()
					w.promMetrics.ActiveRPC.WithLabelValues(url).Set(1)
					break
				}
				client.Close()
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

			rpcIndex++
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
		w.configLock.Lock()
		w.sessCancel = sessCancel
		outPath := w.cfg.Output
		w.configLock.Unlock()

		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Failed to open output file: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var wg sync.WaitGroup

		wg.Add(1)
		go w.startWatchdog(sessCtx, client, &wg, sessCancel)

		wg.Add(1)
		go w.subscribeDeployments(sessCtx, client, outFile, &wg, sessCancel)

		w.configLock.RLock()
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
		if w.cfg.Events.Approvals {
			wg.Add(1)
			go w.subscribeApprovals(sessCtx, client, outFile, &wg, sessCancel)
		}
		if w.cfg.Events.OwnershipTransfers {
			wg.Add(1)
			go w.subscribeOwnershipTransfers(sessCtx, client, outFile, &wg, sessCancel)
		}
		w.configLock.RUnlock()

		<-sessCtx.Done()
		client.Close()
		if err := outFile.Close(); err != nil {
			log.Printf("Error closing session output file: %v", err)
		}
		wg.Wait()
		log.Println("Session ended, reconnecting...")

		// Rotate to the next RPC for the next session attempt
		rpcIndex++
	}
}

func (w *Watcher) loadConfig(path string) {
	cfg, err := loadConfiguration(path)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}
	w.cfg = *cfg

	val, _ := new(big.Int).SetString(w.cfg.WhaleThreshold, 10)
	w.whaleThreshold = val
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

func (w *Watcher) watchConfig(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(w.configPath)
			if err != nil {
				continue
			}
			if !info.ModTime().Equal(w.lastConfigModTime) {
				w.lastConfigModTime = info.ModTime()
				w.reloadConfig()
			}
		}
	}
}

func (w *Watcher) reloadConfig() {
	log.Println("Reloading configuration...")

	newCfg, err := loadConfiguration(w.configPath)
	if err != nil {
		log.Printf("Failed to load config for reload: %v", err)
		return
	}
	if err := validateConfig(newCfg); err != nil {
		log.Printf("Config validation failed during reload: %v", err)
		return
	}

	newWhaleThreshold, _ := new(big.Int).SetString(newCfg.WhaleThreshold, 10)

	w.configLock.Lock()
	defer w.configLock.Unlock()

	w.cfg = *newCfg
	w.whaleThreshold = newWhaleThreshold

	newRPCStates := make([]*RPCState, len(newCfg.RPC))
	for i, rpcCfg := range newCfg.RPC {
		url := buildRPCURL(rpcCfg.URL, rpcCfg.APIKey)
		found := false
		for _, oldState := range w.rpcStates {
			if oldState.URL == url {
				newRPCStates[i] = oldState
				found = true
				break
			}
		}
		if !found {
			newRPCStates[i] = &RPCState{URL: url}
		}
	}
	w.rpcStates = newRPCStates

	w.dexPairs = nil
	w.dexSwaps = nil
	for _, d := range w.cfg.Dexes {
		w.dexPairs = append(w.dexPairs, common.HexToHash(d.PairCreatedTopic))
		w.dexSwaps = append(w.dexSwaps, common.HexToHash(d.SwapTopic))
	}

	w.lock.Lock()
	w.loadWatchedContracts()
	w.lock.Unlock()

	log.Println("Configuration reloaded successfully. Restarting session...")
	if w.sessCancel != nil {
		w.sessCancel()
	}
}

func (w *Watcher) startWatchdog(ctx context.Context, client EthClient, wg *sync.WaitGroup, cancel context.CancelFunc) {
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

func (w *Watcher) subscribeDeployments(ctx context.Context, client EthClient, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()

	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(ctx, headers)
	if err != nil {
		log.Printf("Header subscription failed: %v", err)
		cancel()
		return
	}

	// Semaphore to limit concurrent analysis and RPC calls
	w.configLock.RLock()
	sem := make(chan struct{}, w.cfg.Concurrency)
	w.configLock.RUnlock()

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

			var wg sync.WaitGroup
			for _, tx := range block.Transactions() {
				wg.Add(1)
				go func(tx *types.Transaction) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					if tx.To() != nil {
						return
					}

					receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
					if err != nil || receipt.ContractAddress == (common.Address{}) {
						return
					}

					code, err := client.CodeAt(context.Background(), receipt.ContractAddress, nil)
					if err != nil || len(code) == 0 {
						return
					}

					tokenType := detectTokenType(code)
					if tokenType == "" {
						return
					}

					from, err := types.Sender(types.LatestSignerForChainID(w.chainID), tx)
					if err != nil {
						return
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

					analysisStart := time.Now()
					analysisFlags, analysisScore := analyzeCode(code)
					w.promMetrics.CodeAnalysisDuration.Observe(time.Since(analysisStart).Seconds())
					for _, flag := range analysisFlags {
						w.promMetrics.CodeAnalysisFlags.WithLabelValues(flag).Inc()
					}
					flags := []string{"NewContract"}
					flags = append(flags, analysisFlags...)

					w.writeEvent(out, Finding{
						Contract:  addr,
						Deployer:  from.Hex(),
						Block:     receipt.BlockNumber.Uint64(),
						TokenType: tokenType,
						RiskScore: 10 + analysisScore,
						Flags:     flags,
						TxHash:    tx.Hash().Hex(),
					})

					w.writeStats()
				}(tx)
			}
			wg.Wait()
		}
	}
}

func (w *Watcher) subscribeLogs(ctx context.Context, client EthClient, query ethereum.FilterQuery, handler func(types.Log), wg *sync.WaitGroup, cancel context.CancelFunc, name string) {
	defer wg.Done()

	logsChan := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(ctx, query, logsChan)
	if err != nil {
		log.Printf("%s subscription failed: %v", name, err)
		cancel()
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sub.Err():
			log.Printf("%s subscription error: %v", name, err)
			cancel()
			return

		case vLog := <-logsChan:
			handler(vLog)
		}
	}
}

func (w *Watcher) subscribeTransfers(ctx context.Context, client EthClient, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{{w.transferSig}},
	}
	w.subscribeLogs(ctx, client, query, func(log types.Log) { w.handleTransfer(log, out) }, wg, cancel, "Transfer")
}

func (w *Watcher) subscribeLiquidityAndTrades(ctx context.Context, client EthClient, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{append(w.dexPairs, w.dexSwaps...)},
	}
	w.subscribeLogs(ctx, client, query, func(log types.Log) { w.handleLiquidityOrTrade(log, out) }, wg, cancel, "Liquidity")
}

func (w *Watcher) subscribeFlashLoans(ctx context.Context, client EthClient, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{{w.flashLoanSig}},
	}
	w.subscribeLogs(ctx, client, query, func(log types.Log) { w.handleFlashLoan(log, out) }, wg, cancel, "FlashLoan")
}

func (w *Watcher) subscribeApprovals(ctx context.Context, client EthClient, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{{w.approvalSig}},
	}
	w.subscribeLogs(ctx, client, query, func(log types.Log) { w.handleApproval(log, out) }, wg, cancel, "Approval")
}

func (w *Watcher) subscribeOwnershipTransfers(ctx context.Context, client EthClient, out *os.File, wg *sync.WaitGroup, cancel context.CancelFunc) {
	query := ethereum.FilterQuery{
		Topics: [][]common.Hash{{w.ownershipTransferredSig}},
	}
	w.subscribeLogs(ctx, client, query, func(log types.Log) { w.handleOwnershipTransfer(log, out) }, wg, cancel, "OwnershipTransfer")
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

	w.configLock.RLock()
	whaleThreshold := w.whaleThreshold
	w.configLock.RUnlock()
	if whaleThreshold != nil && strings.EqualFold(state.TokenType, "ERC20") && len(vLog.Data) > 0 {
		val := new(big.Int).SetBytes(vLog.Data)
		if val.Cmp(whaleThreshold) >= 0 {
			flags = append(flags, "WhaleTransfer")
			score += 25
		}
	}

	if score > 100 {
		score = 100
	}

	w.writeEvent(out, Finding{
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
		w.writeEvent(out, f)
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
	w.writeEvent(out, f)
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

	w.writeEvent(out, Finding{
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

func (w *Watcher) handleApproval(vLog types.Log, out *os.File) {
	if len(vLog.Topics) < 3 {
		return
	}

	contract := strings.ToLower(vLog.Address.Hex())

	w.lock.Lock()
	state, ok := w.tracked[contract]
	if !ok {
		w.lock.Unlock()
		return
	}

	w.stats.Approvals++
	w.promMetrics.ApprovalsDetected.Inc()
	w.lock.Unlock()

	log.Printf("Approval detected on %s", contract)

	flags := []string{"ApprovalDetected"}
	score := 10

	if len(vLog.Data) > 0 {
		val := new(big.Int).SetBytes(vLog.Data)
		// Check for Infinite Approval (2^256 - 1)
		maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
		if val.Cmp(maxUint256) == 0 {
			flags = append(flags, "InfiniteApproval")
			score += 40
		} else {
			w.configLock.RLock()
			whaleThreshold := w.whaleThreshold
			w.configLock.RUnlock()
			if whaleThreshold != nil && val.Cmp(whaleThreshold) >= 0 {
				flags = append(flags, "LargeApproval")
				score += 20
			}
		}
	}

	w.writeEvent(out, Finding{
		Contract:  contract,
		Deployer:  state.Deployer,
		Block:     uint64(vLog.BlockNumber),
		TokenType: state.TokenType,
		RiskScore: score,
		Flags:     flags,
		TxHash:    vLog.TxHash.Hex(),
	})
	w.writeStats()
}

func (w *Watcher) handleOwnershipTransfer(vLog types.Log, out *os.File) {
	if len(vLog.Topics) < 3 {
		return
	}

	contract := strings.ToLower(vLog.Address.Hex())

	w.lock.Lock()
	state, ok := w.tracked[contract]
	if !ok {
		w.lock.Unlock()
		return
	}

	w.stats.OwnershipTransfers++
	w.promMetrics.OwnershipTransfersDetected.Inc()
	w.lock.Unlock()

	log.Printf("Ownership transfer detected on %s", contract)

	newOwner := common.HexToAddress(vLog.Topics[2].Hex())
	flags := []string{"OwnershipTransferred"}
	score := 10

	if newOwner == (common.Address{}) {
		flags = append(flags, "OwnershipRenounced")
		score += 40
	}

	w.writeEvent(out, Finding{
		Contract:  contract,
		Deployer:  state.Deployer,
		Block:     uint64(vLog.BlockNumber),
		TokenType: state.TokenType,
		RiskScore: score,
		Flags:     flags,
		TxHash:    vLog.TxHash.Hex(),
	})
	w.writeStats()
}

func detectTokenType(code []byte) string {
	switch {
	case bytes.Contains(code, []byte{0xa9, 0x05, 0x9c, 0xbb}):
		return "ERC20"
	case bytes.Contains(code, []byte{0x80, 0xac, 0x58, 0xcd}):
		return "ERC721"
	case bytes.Contains(code, []byte{0xd9, 0xb6, 0x7a, 0x26}):
		return "ERC1155"
	default:
		return ""
	}
}

func analyzeCode(code []byte) ([]string, int) {
	var flags []string
	score := 0
	
	// Track detected features to avoid duplicates
	detected := make(map[string]bool)
	addFlag := func(flag string, s int) {
		if !detected[flag] {
			detected[flag] = true
			flags = append(flags, flag)
			score += s
		}
	}

	// Known malicious/high-risk addresses (e.g. Tornado Cash Router)
	tornadoRouter := common.HexToAddress("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b").Bytes()
	
	// Function selectors map (4 bytes)
	selectors := map[[4]byte]struct{ flag string; score int }{
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
	}
	
	// Special signatures
	transferSig := [4]byte{0xa9, 0x05, 0x9c, 0xbb}
	hasTransferSig := false
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
	hasInvalid := false

	hasAddSubMul := false
	hasCalldataLoad := false
	hasPanic := false
	hasReentrancyGuard := false

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

				// Check signatures in PUSH data
				if len(lastPushData) >= 4 {
					// Check 4-byte selectors
					// We check the first 4 bytes of the push data
					var sig [4]byte
					copy(sig[:], lastPushData)
					
					if sig == transferSig {
						hasTransferSig = true
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
			} else {
				lastPushData = nil
			}
			lastOp = op
			pc += pushBytes + 1
			continue
		}
		
		// Check for Fake Return Pattern (PUSH1 01 ... RETURN)
		// 600160005260206000f3
		if op == 0x60 && bytes.HasPrefix(code[pc:], fakeReturnSig) {
			addFlag("FakeReturn", 20)
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
			}
		case 0x38: // CODESIZE
			if !hasCodeSize {
				hasCodeSize = true
				addFlag("SuspiciousCodeSize", 5)
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
				addFlag("Timestamp", 5)
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
			canSendEth = true
		case 0xFD: // REVERT
			hasRevert = true
		case 0xF3: // RETURN
			hasReturn = true
		case 0xFE: // INVALID
			hasInvalid = true
		case 0x00: // STOP
			hasStop = true
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
	if hasReentrancyGuard {
		addFlag("ReentrancyGuard", 0)
	}

	return flags, score
}

func loadConfiguration(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config open error: %v", err)
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config decode error: %v", err)
	}

	if cfg.Output == "" {
		cfg.Output = "eth-watch-events.jsonl"
	}
	if cfg.Log == "" {
		cfg.Log = "eth-watch.log"
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 20
	}

	return &cfg, nil
}

func validateConfig(cfg *Config) error {
	if len(cfg.RPC) == 0 {
		return fmt.Errorf("rpc list required in config")
	}

	hasValidRPC := false
	for _, r := range cfg.RPC {
		if r.URL != "" {
			hasValidRPC = true
			break
		}
	}
	if !hasValidRPC {
		return fmt.Errorf("at least one valid RPC URL is required")
	}

	if cfg.WhaleThreshold != "" {
		_, ok := new(big.Int).SetString(cfg.WhaleThreshold, 10)
		if !ok {
			return fmt.Errorf("invalid whale_threshold: %s", cfg.WhaleThreshold)
		}
	}
	return nil
}

func buildRPCURL(base, key string) string {
	if key == "" {
		return base
	}
	if strings.HasPrefix(key, "?") || strings.HasSuffix(base, "/") {
		return base + key
	}
	return base + "/" + key
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

func (w *Watcher) writeEvent(out *os.File, f Finding) {
	w.fileLock.Lock()
	defer w.fileLock.Unlock()
	writer := bufio.NewWriter(out)
	b, err := json.Marshal(f)
	if err != nil {
		log.Printf("json marshal error: %v", err)
		return
	}
	_, _ = writer.Write(b)
	_, _ = writer.Write([]byte("\n"))
	_ = writer.Flush()
}

func (w *Watcher) writeStats() {
	w.lock.RLock()
	defer w.lock.RUnlock()

	uptime := time.Since(w.startTime).Round(time.Second)
	log.Printf(
		"stats uptime=%s contracts=%d mints=%d liquidity=%d trades=%d flashloans=%d approvals=%d ownership=%d",
		uptime,
		w.stats.NewContracts,
		w.stats.Mints,
		w.stats.Liquidity,
		w.stats.Trades,
		w.stats.FlashLoans,
		w.stats.Approvals,
		w.stats.OwnershipTransfers,
	)
}
