package main

import (
	"eth-watch/pkg/analyzer"
	"eth-watch/pkg/analyzer/checks"
)

type Analyzer struct {
	inner *analyzer.Analyzer
	ctx   *analyzer.ScanContext
}

func NewAnalyzer(code []byte) *Analyzer {
	a := analyzer.NewAnalyzer(code)
	a.CheckSet = checks.DefaultCheckSet()
	return &Analyzer{
		inner: a,
		ctx:   a.Ctx,
	}
}

func (a *Analyzer) Reset(code []byte) {
	a.inner.Reset(code)
	a.ctx = a.inner.Ctx
}

func (a *Analyzer) UpdateHeuristics(enabled, disabled map[string]bool) {
	a.inner.UpdateHeuristics(enabled, disabled)
}

func (a *Analyzer) Analyze() ([]string, int) {
	return a.inner.Analyze()
}

func bytesToInt(b []byte) int {
	return analyzer.BytesToInt(b)
}
