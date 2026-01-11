package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

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
	AnalyzerPoolAllocations    prometheus.Counter
	CodeAnalysisDuration       prometheus.Histogram
	ActiveSubscriptions        prometheus.Gauge
}

func NewWatcherMetrics() WatcherMetrics {
	return WatcherMetrics{
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
		AnalyzerPoolAllocations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "eth_watcher_analyzer_pool_allocations_total",
			Help: "Total number of analyzer objects created by the pool",
		}),
		CodeAnalysisDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "eth_watcher_code_analysis_duration_seconds",
			Help:    "Time taken to analyze contract bytecode in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		ActiveSubscriptions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "eth_watcher_active_subscriptions",
			Help: "Current number of active WebSocket subscriptions",
		}),
	}
}

func RegisterMetrics(w WatcherMetrics) {
	prometheus.MustRegister(w.ContractsDiscovered, w.MintsDetected, w.LiquidityEvents, w.TradesDetected, w.FlashLoansDetected, w.ApprovalsDetected, w.OwnershipTransfersDetected, w.RPCStalled, w.ActiveRPC, w.RPCLatency, w.RPCCircuitBreakerTrips, w.CodeAnalysisFlags, w.ChainIDFetchFailures, w.AnalyzerPoolAllocations, w.CodeAnalysisDuration, w.ActiveSubscriptions)
}
