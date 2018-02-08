package core

import (
	"context"
	"github.com/google/gopacket"
)

type PonSimInterface interface {
	Start(context.Context)

	Stop(context.Context)

	GetAddress() string

	GetPort() int32

	Forward(context.Context, int, gopacket.Packet) error
}
