package core

type PonSimDeviceState uint8

const (
	DISCONNECTED_FROM_PON PonSimDeviceState = iota
	CONNECTED_TO_PON
	REGISTERED_WITH_OLT
	CONNECTED_IO_INTERFACE
)

// Execute state string equivalents
var PonSimDeviceStateEnum = []string{
	"DISCONNECTED_FROM_PON",
	"CONNECTED_TO_PON",
	"REGISTERED_WITH_OLT",
	"CONNECTED_IO_INTERFACE",
}

func (s PonSimDeviceState) String() string {
	return PonSimDeviceStateEnum[s]
}
