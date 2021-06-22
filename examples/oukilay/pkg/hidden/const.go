package hidden

// actions
const (
	KMsgAction uint64 = iota + 1
	OverrideContent
	OverrideReturn
	HideFile
)

// progs
const (
	KMsgProg = iota + KMsgAction
	OverrideContentProg

	FillWithZeroProg = 10
	OverrideGetDents = 11
)
