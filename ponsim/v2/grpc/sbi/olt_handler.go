/*
 * Copyright 2017-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sbi

import (
	"context"
	"github.com/google/uuid"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/ponsim/v2/core"
	"github.com/opencord/voltha/protos/go/ponsim"
	"github.com/sirupsen/logrus"
)

type PonSimOltHandler struct {
	olt *core.PonSimOltDevice
}

func NewPonSimOltHandler(olt *core.PonSimOltDevice) *PonSimOltHandler {
	var handler *PonSimOltHandler

	handler = &PonSimOltHandler{olt: olt}

	return handler
}

func (h *PonSimOltHandler) Register(
	ctx context.Context,
	request *ponsim.RegistrationRequest,
) (*ponsim.RegistrationReply, error) {
	common.Logger().WithFields(logrus.Fields{
		"handler": h,
	}).Info("Registering device")

	onu := &core.PonSimOnuDevice{
		PonSimDevice: core.PonSimDevice{
			Address: request.Address, Port: request.Port, //GrpcSecurity: h.olt.GrpcSecurity,
		}}
	onu.SerialNumber = request.SerialNumber

	if assignedPort, err := h.olt.AddOnu(onu); assignedPort == -1 || err != nil {
		return &ponsim.RegistrationReply{
			Id:            uuid.New().String(),
			Status:        ponsim.RegistrationReply_FAILED,
			StatusMessage: "Failed to register ONU",
			ParentAddress: common.GetInterfaceIP(h.olt.ExternalIf),
			ParentPort:    h.olt.Port,
			AssignedPort:  assignedPort,
		}, err
	} else {
		common.Logger().WithFields(logrus.Fields{
			"handler": h,
			"onus":    h.olt.GetOnus(),
		}).Debug("ONU Added")

		return &ponsim.RegistrationReply{
			Id:            uuid.New().String(),
			Status:        ponsim.RegistrationReply_REGISTERED,
			StatusMessage: "Successfully registered ONU",
			ParentAddress: common.GetInterfaceIP(h.olt.ExternalIf),
			ParentPort:    h.olt.Port,
			AssignedPort:  assignedPort,
		}, nil

	}
}
