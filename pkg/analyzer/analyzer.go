package analyzer

type LoopSnapshot struct {
	CountCalls, CountDelegateCalls, CountCreates, CountSelfDestructs, CountGasOps, CountSstore int
}

type ScanContext struct {
	Code []byte
	PC   int
	Op   byte

	Flags    []string
	Score    int
	Detected map[string]bool // Used for flag presence and inter-check communication

	LastOp           byte
	PushData         []byte
	LastDivPC        int
	LastTimestampPC  int
	LastOriginPC     int
	LastStaticCallPC int
	LastSelectorPC   int
	LastSelector     [4]byte
	JumpDests        map[int]LoopSnapshot

	CountCalls         int
	CountDelegateCalls int
	CountCreates       int
	CountSelfDestructs int
	CountGasOps        int
	CountSload         int
	CountSstore        int
	CountLogs          int

	WrittenSlots map[int]bool
	ReadSlots    map[int]bool

	EnabledHeuristics  map[string]bool
	DisabledHeuristics map[string]bool
}

func (ctx *ScanContext) AddFlag(flag string, score int) {
	if ctx.Detected[flag] {
		return
	}
	if len(ctx.DisabledHeuristics) > 0 && ctx.DisabledHeuristics[flag] {
		return
	}
	if len(ctx.EnabledHeuristics) > 0 && !ctx.EnabledHeuristics[flag] {
		return
	}
	ctx.Detected[flag] = true
	ctx.Flags = append(ctx.Flags, flag)
	ctx.Score += score
}

type Check interface {
	Name() string
	Accumulate(ctx *ScanContext, emit func(flag string, score int))
	Finalize(ctx *ScanContext, emit func(flag string, score int))
	Reset()
}

type CheckSet struct {
	checks []Check
}

func (cs *CheckSet) Register(c Check) {
	cs.checks = append(cs.checks, c)
}

type Analyzer struct {
	Ctx      *ScanContext
	CheckSet *CheckSet
}

func NewAnalyzer(code []byte) *Analyzer {
	return &Analyzer{
		Ctx: &ScanContext{
			Code:             code,
			Detected:         make(map[string]bool),
			JumpDests:        make(map[int]LoopSnapshot),
			LastDivPC:        -1,
			LastTimestampPC:  -1,
			LastStaticCallPC: -1,
			LastOriginPC:     -1,
			LastSelectorPC:   -1,
			WrittenSlots:     make(map[int]bool),
			ReadSlots:        make(map[int]bool),
		},
		CheckSet: &CheckSet{},
	}
}

func (a *Analyzer) Reset(code []byte) {
	ctx := a.Ctx
	ctx.Code = code
	ctx.PC = 0
	ctx.Flags = ctx.Flags[:0]
	ctx.Score = 0
	clear(ctx.Detected)
	clear(ctx.JumpDests)
	ctx.LastOp = 0
	ctx.PushData = nil
	ctx.LastDivPC = -1
	ctx.LastTimestampPC = -1
	ctx.LastOriginPC = -1
	ctx.LastStaticCallPC = -1
	ctx.LastSelectorPC = -1
	ctx.LastSelector = [4]byte{}
	ctx.CountCalls = 0
	ctx.CountDelegateCalls = 0
	ctx.CountCreates = 0
	ctx.CountSelfDestructs = 0
	ctx.CountGasOps = 0
	ctx.CountSload = 0
	ctx.CountSstore = 0
	ctx.CountLogs = 0
	clear(ctx.WrittenSlots)
	clear(ctx.ReadSlots)

	for _, c := range a.CheckSet.checks {
		c.Reset()
	}
}

func (a *Analyzer) UpdateHeuristics(enabled, disabled map[string]bool) {
	a.Ctx.EnabledHeuristics = enabled
	a.Ctx.DisabledHeuristics = disabled
}

func (a *Analyzer) Analyze() ([]string, int) {
	return a.CheckSet.Analyze(a.Ctx)
}

func (cs *CheckSet) Analyze(ctx *ScanContext) ([]string, int) {
	emit := func(flag string, score int) {
		ctx.AddFlag(flag, score)
	}

	// Pre-scan
	ctx.PC = -1
	for _, c := range cs.checks {
		c.Accumulate(ctx, emit)
	}
	ctx.PC = 0

	for ctx.PC < len(ctx.Code) {
		op := ctx.Code[ctx.PC]
		ctx.Op = op

		cs.advanceDecoder(ctx)

		for _, c := range cs.checks {
			c.Accumulate(ctx, emit)
		}

		if op >= 0x60 && op <= 0x7F {
			ctx.PC += int(op-0x5F) + 1
		} else {
			ctx.PC++
		}
		ctx.LastOp = op
	}

	for _, c := range cs.checks {
		c.Finalize(ctx, emit)
	}

	return ctx.Flags, ctx.Score
}

func (cs *CheckSet) advanceDecoder(ctx *ScanContext) {
	op := ctx.Op

	if op >= 0x60 && op <= 0x7F {
		pushBytes := int(op - 0x5F)
		if ctx.PC+1+pushBytes <= len(ctx.Code) {
			ctx.PushData = ctx.Code[ctx.PC+1 : ctx.PC+1+pushBytes]
		} else {
			ctx.PushData = nil
		}
	}

	switch op {
	case 0x54: // SLOAD
		ctx.CountSload++
	case 0x55: // SSTORE
		ctx.CountSstore++
	case 0xF0, 0xF5: // CREATE, CREATE2
		ctx.CountCreates++
	case 0xF1, 0xF2, 0xF4, 0xFA: // CALL, CALLCODE, DELEGATECALL, STATICCALL
		if op == 0xF4 {
			ctx.CountDelegateCalls++
		} else {
			ctx.CountCalls++
		}
	case 0xFF: // SELFDESTRUCT
		ctx.CountSelfDestructs++
	case 0x5A: // GAS
		ctx.CountGasOps++
	case 0xA0, 0xA1, 0xA2, 0xA3, 0xA4: // LOG0...LOG4
		ctx.CountLogs++
	case 0x5B: // JUMPDEST
		ctx.JumpDests[ctx.PC] = LoopSnapshot{
			ctx.CountCalls, ctx.CountDelegateCalls, ctx.CountCreates, ctx.CountSelfDestructs, ctx.CountGasOps, ctx.CountSstore,
		}
	}
}

func BytesToInt(b []byte) int {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	res := 0
	for _, v := range b {
		res = (res << 8) | int(v)
	}
	return res
}
