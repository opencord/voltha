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
