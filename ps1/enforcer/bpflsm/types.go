package bpflsm

type eventType struct {
	Type   uint8
	Action uint8
}

func getConnectionType(c uint8) string {
	switch c {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

func getActionType(a uint8) string {
	switch a {
	case 1:
		return "PASS"
	case 2:
		return "DROP"
	default:
		return "INVALID"
	}
}
