package checks

import "eth-watch/pkg/analyzer"

func DefaultCheckSet() *analyzer.CheckSet {
	cs := &analyzer.CheckSet{}
	cs.Register(&SignaturesCheck{})
	cs.Register(&OpcodeCheck{})
	cs.Register(&ControlFlowCheck{})
	cs.Register(&CompositeCheck{})
	cs.Register(&RugpullCheck{})
	return cs
}
