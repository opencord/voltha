package nbi

import (
	"context"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/opencord/voltha/ponsim/v2/core"
	"github.com/opencord/voltha/protos/go/voltha"
)

type XPonSimHandler struct {
	device *core.XPonSimDevice
}

func NewXPonSimHandler() *XPonSimHandler {
	var handler *XPonSimHandler
	handler = &XPonSimHandler{}
	return handler
}

func (handler *XPonSimHandler) CreateInterface(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.CreateInterface(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) UpdateInterface(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.UpdateInterface(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) RemoveInterface(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.RemoveInterface(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) CreateTcont(
	ctx context.Context,
	config *voltha.TcontInterfaceConfig,
) (*empty.Empty, error) {
	handler.device.CreateTcont(ctx, config.TcontsConfigData, config.TrafficDescriptorProfileConfigData)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) UpdateTcont(
	ctx context.Context,
	config *voltha.TcontInterfaceConfig,
) (*empty.Empty, error) {
	handler.device.UpdateTcont(ctx, config.TcontsConfigData, config.TrafficDescriptorProfileConfigData)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) RemoveTcont(
	ctx context.Context,
	config *voltha.TcontInterfaceConfig,
) (*empty.Empty, error) {
	handler.device.RemoveTcont(ctx, config.TcontsConfigData, config.TrafficDescriptorProfileConfigData)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) CreateGemport(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.CreateGemport(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) UpdateGemport(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.UpdateGemport(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) RemoveGemport(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.RemoveGemport(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) CreateMulticastGemport(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.CreateMulticastGemport(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) UpdateMulticastGemport(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.UpdateMulticastGemport(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) RemoveMulticastGemport(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.RemoveMulticastGemport(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) CreateMulticastDistributionSet(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.CreateMulticastDistributionSet(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) UpdateMulticastDistributionSet(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.UpdateMulticastDistributionSet(ctx, config)
	return &empty.Empty{}, nil
}
func (handler *XPonSimHandler) RemoveMulticastDistributionSet(
	ctx context.Context,
	config *voltha.InterfaceConfig,
) (*empty.Empty, error) {
	handler.device.RemoveMulticastDistributionSet(ctx, config)
	return &empty.Empty{}, nil
}
