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
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/ponsim/v2/core"
	"github.com/opencord/voltha/protos/go/ponsim"
	"github.com/sirupsen/logrus"
	"io"
)

type PonSimCommonHandler struct {
	device core.PonSimInterface
}

/*
NewPonSimCommonHandler instantiates a handler for common GRPC servicing methods
*/
func NewPonSimCommonHandler(device core.PonSimInterface) *PonSimCommonHandler {
	var handler *PonSimCommonHandler

	handler = &PonSimCommonHandler{device: device}

	return handler
}

/*
ProcessData handles and forwards streaming INGRESS/EGRESS packets
*/
func (h *PonSimCommonHandler) ProcessData(stream ponsim.PonSimCommon_ProcessDataServer) error {
	common.Logger().WithFields(logrus.Fields{
		"handler": h,
	}).Debug("Processing data")

	var err error
	var data *ponsim.IncomingData

	for {

		if data, err = stream.Recv(); err == io.EOF {
			common.Logger().WithFields(logrus.Fields{
				"handler": h,
			}).Warn("Streaming channel was closed")
			return stream.SendAndClose(&empty.Empty{})
		} else if err != nil {
			common.Logger().WithFields(logrus.Fields{
				"handler": h,
				"error":   err.Error(),
			}).Warn("Error occurred with stream")
			return err
		}

		frame := gopacket.NewPacket(data.Payload, layers.LayerTypeEthernet, gopacket.Default)

		h.device.Forward(
			context.Background(),
			int(data.Port),
			frame,
		)
		common.Logger().WithFields(logrus.Fields{
			"handler": h,
			"frame":   frame,
			"port":    data.Port,
		}).Debug("Retrieved and forwarded packet")

	}

	return nil
}
