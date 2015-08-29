package ecn

// Explicit Congestion Notification

const (
	NonECT = 0 // Non ECN Capable Transport
	ECT0   = 2 // ECN Capable (0)
	ECT1   = 1 // ECN Capable (1)
	CE     = 3 // Congestion Encountered
)
