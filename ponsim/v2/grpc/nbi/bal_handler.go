package nbi

import (
	"context"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/bal"
)

// TODO: fix BAL function parameters and returns

type BalHandler struct {
}

func NewBalHandler() *BalHandler {
	var handler *BalHandler
	handler = &BalHandler{}
	return handler
}

func (handler *BalHandler) BalApiInit(
	ctx context.Context,
	request *bal.BalInit,
) (*bal.BalErr, error) {
	common.Logger().Info("BalApiInit Called", ctx, request)
	return &bal.BalErr{Err: bal.BalErrno_BAL_ERR_OK}, nil
}

func (handler *BalHandler) BalApiFinish(
	ctx context.Context,
	request *bal.BalCfg,
) (*bal.BalErr, error) {
	common.Logger().Info("BalApiFinish Called", ctx, request)
	return &bal.BalErr{Err: bal.BalErrno_BAL_ERR_OK}, nil
}

func (handler *BalHandler) BalCfgSet(
	ctx context.Context,
	request *bal.BalCfg,
) (*bal.BalErr, error) {
	common.Logger().Info("BalCfgSet Called", ctx, request)
	return &bal.BalErr{Err: bal.BalErrno_BAL_ERR_OK}, nil
}

func (handler *BalHandler) BalCfgClear(
	ctx context.Context,
	request *bal.BalKey,
) (*bal.BalErr, error) {
	common.Logger().Info("BalCfgClear Called", ctx, request)
	return &bal.BalErr{Err: bal.BalErrno_BAL_ERR_OK}, nil
}

func (handler *BalHandler) BalCfgGet(
	ctx context.Context,
	request *bal.BalKey,
) (*bal.BalCfg, error) {
	common.Logger().Info("BalCfgGet Called", ctx, request)
	return &bal.BalCfg{}, nil
}

func (handler *BalHandler) BalApiReboot(
	ctx context.Context,
	request *bal.BalReboot,
) (*bal.BalErr, error) {
	common.Logger().Info("BalApiReboot Called", ctx, request)
	return &bal.BalErr{Err: bal.BalErrno_BAL_ERR_OK}, nil
}

func (handler *BalHandler) BalApiHeartbeat(
	ctx context.Context,
	request *bal.BalHeartbeat,
) (*bal.BalRebootState, error) {
	common.Logger().Info("BalApiHeartbeat Called", ctx, request)
	return &bal.BalRebootState{}, nil
}

func (handler *BalHandler) BalCfgStatGet(
	ctx context.Context,
	request *bal.BalInterfaceKey,
) (*bal.BalInterfaceStat, error) {
	common.Logger().Info("BalCfgStatGet Called", ctx, request)
	return &bal.BalInterfaceStat{}, nil
}
