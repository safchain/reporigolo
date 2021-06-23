package hidden

// actions
const (
	KMsgAction      uint64 = 1
	OverrideContent uint64 = 2
	OverrideReturn  uint64 = 4
	HideFile        uint64 = 8
)

// progs
const (
	KMsgProg = iota + KMsgAction
	OverrideContentProg

	FillWithZeroProg = 10
	OverrideGetDents = 11
)
