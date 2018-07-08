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
package grpc

import (
	"net"

	"context"
	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/ponsim/v2/core"
	"github.com/opencord/voltha/ponsim/v2/grpc/nbi"
	"github.com/opencord/voltha/ponsim/v2/grpc/sbi"
	"github.com/opencord/voltha/protos/go/bal"
	"github.com/opencord/voltha/protos/go/ponsim"
	"github.com/opencord/voltha/protos/go/voltha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"strconv"
	"strings"
)

type GrpcServer struct {
	gs       *grpc.Server
	address  string
	port     int32
	secure   bool
	services []func(*grpc.Server)

	*GrpcSecurity
}

/*
Instantiate a GRPC server data structure
*/
func NewGrpcServer(
	address string,
	port int32,
	certs *GrpcSecurity,
	secure bool,
) *GrpcServer {
	server := &GrpcServer{
		address:      address,
		port:         port,
		secure:       secure,
		GrpcSecurity: certs,
	}
	return server
}

/*
Start prepares the GRPC server and starts servicing requests
*/
func (s *GrpcServer) Start(ctx context.Context) {
	host := strings.Join([]string{
		s.address,
		strconv.Itoa(int(s.port)),
	}, ":")

	lis, err := net.Listen("tcp", host)
	if err != nil {
		common.Logger().Fatalf("failed to listen: %v", err)
	}

	if s.secure {
		creds, err := credentials.NewServerTLSFromFile(s.CertFile, s.KeyFile)
		if err != nil {
			common.Logger().Fatalf("could not load TLS keys: %s", err)
		}
		s.gs = grpc.NewServer(grpc.Creds(creds))

	} else {
		common.Logger().Println("In DEFAULT\n")
		s.gs = grpc.NewServer()
	}

	// Register all required services
	for _, service := range s.services {
		service(s.gs)
	}

	if err := s.gs.Serve(lis); err != nil {
		common.Logger().Fatalf("failed to serve: %v\n", err)
	}
}

/*
Stop servicing GRPC requests
*/
func (s *GrpcServer) Stop() {
	s.gs.Stop()
}

/*
AddService appends a generic service request function
*/
func (s *GrpcServer) AddService(
	registerFunction func(*grpc.Server, interface{}),
	handler interface{},
) {
	s.services = append(s.services, func(gs *grpc.Server) { registerFunction(gs, handler) })
}

/*
AddPonSimService appends service request functions for PonSim devices
*/
func (s *GrpcServer) AddPonSimService(device core.PonSimInterface) {
	s.services = append(
		s.services,
		func(gs *grpc.Server) {
			voltha.RegisterPonSimServer(gs, nbi.NewPonSimHandler(device))
		},
	)
}

/*
AddCommonService appends service request functions common to all PonSim devices
*/
func (s *GrpcServer) AddCommonService(device core.PonSimInterface) {
	s.services = append(
		s.services,
		func(gs *grpc.Server) {
			ponsim.RegisterPonSimCommonServer(gs, sbi.NewPonSimCommonHandler(device))
		},
	)
}

/*
AddOltService appends service request functions specific to OLT devices
*/
func (s *GrpcServer) AddOltService(device core.PonSimInterface) {
	s.services = append(
		s.services,
		func(gs *grpc.Server) {
			ponsim.RegisterPonSimOltServer(
				gs,
				sbi.NewPonSimOltHandler(device.(*core.PonSimOltDevice)),
			)
		},
	)
}

/*
AddXPonService appends service request functions specific to XPonSim
*/
func (s *GrpcServer) AddXPonService() {
	s.services = append(
		s.services,
		func(gs *grpc.Server) {
			voltha.RegisterXPonSimServer(gs, nbi.NewXPonSimHandler())
		},
	)
}

/*
AddBalService appends service request functions specific to BAL
*/
func (s *GrpcServer) AddBalService() {
	s.services = append(
		s.services,
		func(gs *grpc.Server) {
			bal.RegisterBalServer(gs, nbi.NewBalHandler())
		},
	)
}
