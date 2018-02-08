package core

type PonSimApiType uint8

const (
	PONSIM PonSimApiType = iota
	BAL
)

var enum_ponsim_api_types = []string{
	"PONSIM",
	"BAL",
}

func (t PonSimApiType) String() string {
	return enum_ponsim_api_types[t]
}
