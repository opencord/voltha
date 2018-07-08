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
package core

import (
	"context"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/protos/go/bbf_fiber"
	"github.com/opencord/voltha/protos/go/voltha"
	"github.com/sirupsen/logrus"
)

type XPonSimDevice struct {
}

/*

 */
func (d *XPonSimDevice) Start(ctx context.Context) {
}

/*

 */
func (d *XPonSimDevice) Stop(ctx context.Context) {
}

/*

 */
func (d *XPonSimDevice) CreateInterface(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("create-interface-request")
}

/*

 */
func (d *XPonSimDevice) UpdateInterface(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("update-interface-request")
}

/*

 */
func (d *XPonSimDevice) RemoveInterface(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("remove-interface-request")
}

/*

 */
func (d *XPonSimDevice) CreateTcont(ctx context.Context,
	config *bbf_fiber.TcontsConfigData,
	profile *bbf_fiber.TrafficDescriptorProfileData,
) {
	common.Logger().WithFields(logrus.Fields{
		"context":                                ctx,
		"device":                                 d,
		"tcont_config_data":                      config,
		"traffic_descriptor_profile_config_data": profile,
	}).Info("create-tcont-request")
}

/*

 */
func (d *XPonSimDevice) UpdateTcont(
	ctx context.Context,
	config *bbf_fiber.TcontsConfigData,
	profile *bbf_fiber.TrafficDescriptorProfileData,
) {
	common.Logger().WithFields(logrus.Fields{
		"context":                                ctx,
		"device":                                 d,
		"tcont_config_data":                      config,
		"traffic_descriptor_profile_config_data": profile,
	}).Info("update-tcont-request")
}

/*

 */
func (d *XPonSimDevice) RemoveTcont(
	ctx context.Context,
	config *bbf_fiber.TcontsConfigData,
	profile *bbf_fiber.TrafficDescriptorProfileData,
) {
	common.Logger().WithFields(logrus.Fields{
		"context":                                ctx,
		"device":                                 d,
		"tcont_config_data":                      config,
		"traffic_descriptor_profile_config_data": profile,
	}).Info("remove-tcont-request")
}

/*

 */
func (d *XPonSimDevice) CreateGemport(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("create-gemport-request")
}

/*

 */
func (d *XPonSimDevice) UpdateGemport(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("update-gemport-request")
}

/*

 */
func (d *XPonSimDevice) RemoveGemport(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("remove-gemport-request")
}

/*

 */
func (d *XPonSimDevice) CreateMulticastGemport(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("create-multicast-gemport-request")
}

/*

 */
func (d *XPonSimDevice) UpdateMulticastGemport(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("update-multicast-gemport-request")
}

/*

 */
func (d *XPonSimDevice) RemoveMulticastGemport(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("remove-multicast-gemport-request")
}

/*

 */
func (d *XPonSimDevice) CreateMulticastDistributionSet(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("create-multicast-distribution-set-request")
}

/*

 */
func (d *XPonSimDevice) UpdateMulticastDistributionSet(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("update-multicast-distribution-set-request")
}

/*

 */
func (d *XPonSimDevice) RemoveMulticastDistributionSet(ctx context.Context, config *voltha.InterfaceConfig) {
	common.Logger().WithFields(logrus.Fields{
		"context":        ctx,
		"device":         d,
		"interface_type": config.GetInterfaceType(),
		"data":           config,
	}).Info("remove-multicast-distribution-set-request")
}
