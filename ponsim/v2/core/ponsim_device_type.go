package core

type PonSimDeviceType uint8

const (
	OLT PonSimDeviceType = iota
	ONU
)

var enum_ponsim_device_types = []string{
	"OLT",
	"ONU",
}

func (t PonSimDeviceType) String() string {
	return enum_ponsim_device_types[t]
}
