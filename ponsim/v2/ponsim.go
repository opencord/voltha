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
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"

	"github.com/opencord/voltha/ponsim/v2/common"
	"github.com/opencord/voltha/ponsim/v2/core"
	"github.com/opencord/voltha/ponsim/v2/grpc"
)

// TODO: Cleanup logs

const (
	default_name           = "PON"
	default_grpc_port      = 50060
	default_grpc_addr      = ""
	default_device_type    = "OLT"
	default_api_type       = "PONSIM"
	default_internal_if    = "eth0"
	default_external_if    = "eth1"
	default_onus           = 1
	default_alarm_sim      = false
	default_alarm_freq     = 60
	default_quiet          = false
	default_verbose        = false
	default_no_banner      = false
	default_parent_addr    = "olt"
	default_parent_port    = 50060
	default_vcore_endpoint = "vcore"
	default_fluentd_host   = ""
	default_serial_number  = "PSMO12345678"

	default_snapshot_len = 65535
	default_promiscuous  = false

	default_voltha_key  = "pki/voltha.key"
	default_voltha_cert = "pki/voltha.crt"
	default_voltha_ca   = "pki/voltha-CA.pem"
)

var (
	voltha_base = os.Getenv("VOLTHA_BASE")
	certs       *grpc.GrpcSecurity

	name           string = default_name + "_" + device_type
	grpc_port      int    = default_grpc_port
	grpc_addr      string = default_grpc_addr
	device_type    string = default_device_type
	api_type       string = default_api_type
	internal_if    string = default_internal_if
	external_if    string = default_external_if
	onus           int    = default_onus
	alarm_sim      bool   = default_alarm_sim
	alarm_freq     int    = default_alarm_freq
	quiet          bool   = default_quiet
	verbose        bool   = default_verbose
	no_banner      bool   = default_no_banner
	voltha_key     string = default_voltha_key
	voltha_cert    string = default_voltha_cert
	voltha_ca      string = default_voltha_ca
	parent_addr    string = default_parent_addr
	parent_port    int    = default_parent_port
	vcore_endpoint string = default_vcore_endpoint
	fluentd_host   string = default_fluentd_host
	serial_number  string = default_serial_number

	snapshot_len int32 = default_snapshot_len
	promiscuous  bool  = default_promiscuous
)

func init() {
	parseArgs()

	// Enable fluentd support
	if fluentd_host != "" {
		common.Logger().SetFluentd(fluentd_host)
	}

	// Print banner unless no_banner is specified
	if !no_banner {
		printBanner()
	}
}

func parseArgs() {
	var help string

	help = fmt.Sprintf("Name of the PON device")
	flag.StringVar(&grpc_addr, "name", default_name, help)

	help = fmt.Sprintf("Address used to establish GRPC server connection")
	flag.StringVar(&grpc_addr, "grpc_addr", default_grpc_addr, help)

	help = fmt.Sprintf("Port used to establish GRPC server connection")
	flag.IntVar(&grpc_port, "grpc_port", default_grpc_port, help)

	help = fmt.Sprintf("Type of device to simulate (OLT or ONU)")
	flag.StringVar(&device_type, "device_type", default_device_type, help)

	help = fmt.Sprintf("Type of API used to communicate with devices (PONSIM or BAL)")
	flag.StringVar(&api_type, "api_type", default_api_type, help)

	help = fmt.Sprintf("Internal Communication Interface for read/write network traffic")
	flag.StringVar(&internal_if, "internal_if", default_internal_if, help)

	help = fmt.Sprintf("External Communication Interface for read/write network traffic")
	flag.StringVar(&external_if, "external_if", default_external_if, help)

	help = fmt.Sprintf("Enable promiscuous mode on network interfaces")
	flag.BoolVar(&promiscuous, "promiscuous", default_promiscuous, help)

	help = fmt.Sprintf("Number of ONUs to simulate")
	flag.IntVar(&onus, "onus", default_onus, help)

	help = fmt.Sprintf("Suppress debug and info logs")
	flag.BoolVar(&quiet, "quiet", default_quiet, help)

	help = fmt.Sprintf("Enable verbose logging")
	flag.BoolVar(&verbose, "verbose", default_verbose, help)

	help = fmt.Sprintf("Omit startup banner log lines")
	flag.BoolVar(&no_banner, "no_banner", default_no_banner, help)

	help = fmt.Sprintf("Enable generation of simulated alarms")
	flag.BoolVar(&alarm_sim, "alarm_sim", default_alarm_sim, help)

	help = fmt.Sprintf("Frequency of simulated alarms (in seconds)")
	flag.IntVar(&alarm_freq, "alarm_freq", default_alarm_freq, help)

	help = fmt.Sprintf("Address of OLT to connect to")
	flag.StringVar(&parent_addr, "parent_addr", default_parent_addr, help)

	help = fmt.Sprintf("Port of OLT to connect to")
	flag.IntVar(&parent_port, "parent_port", default_parent_port, help)

	help = fmt.Sprintf("Voltha core endpoint address")
	flag.StringVar(&vcore_endpoint, "vcore_endpoint", default_vcore_endpoint, help)

	help = fmt.Sprintf("Fluentd host address")
	flag.StringVar(&fluentd_host, "fluentd", default_fluentd_host, help)

	help = fmt.Sprintf("Serial number of ONU device")
	flag.StringVar(&serial_number, "serial_number", default_serial_number, help)

	flag.Parse()
}

func printBanner() {
	log.Println("    ____  ____  _   _______ ______  ___")
	log.Println("   / __ \\/ __ \\/ | / / ___//  _/  |/  /")
	log.Println("  / /_/ / / / /  |/ /\\__ \\ / // /|_/ / ")
	log.Println(" / ____/ /_/ / /|  /___/ // // /  / /  ")
	log.Println("/_/    \\____/_/ |_//____/___/_/  /_/  ")

	switch device_type {
	case "OLT":
		printOltBanner()
	case "ONU":
		printOnuBanner()
	}

	log.Println("(to stop: press Ctrl-C)")
}
func printOltBanner() {
	log.Println("   ____  __  ______")
	log.Println("  / __ \\/ / /_  __/")
	log.Println(" / / / / /   / /   ")
	log.Println("/ /_/ / /___/ /    ")
	log.Println("\\____/_____/_/     ")
}
func printOnuBanner() {
	log.Println("   ____  _   ____  __")
	log.Println("  / __ \\/ | / / / / /")
	log.Println(" / / / /  |/ / / / / ")
	log.Println("/ /_/ / /|  / /_/ /  ")
	log.Println("\\____/_/ |_/\\____/   ")
}

/*
-----------------------------------------------------------------
*/
type PonSimService struct {
	device core.PonSimInterface
	server *grpc.GrpcServer
}

func (s *PonSimService) Start(ctx context.Context) {
	// GRPC server needs to be secure.
	// Otherwise communication between adapter and simulator does not occur
	s.server = grpc.NewGrpcServer(s.device.GetAddress(), s.device.GetPort(), certs, false)

	// Add GRPC services
	s.server.AddCommonService(s.device)
	s.server.AddPonSimService(s.device)

	// Add OLT specific services
	if device_type == core.OLT.String() {
		s.server.AddOltService(s.device)
	}

	// Add XPON services unless using BAL
	if api_type == core.PONSIM.String() {
		s.server.AddXPonService()
	} else {
		s.server.AddBalService()
	}

	// Start the GRPC server
	go s.server.Start(ctx)

	// Start the PON device
	go s.device.Start(ctx)
}

func (s *PonSimService) Stop(ctx context.Context) {
	// Stop PON device
	s.device.Stop(ctx)

	// Stop GRPC server
	s.server.Stop()
}

func main() {
	var device core.PonSimInterface

	// Init based on type of device
	// Construct OLT/ONU object and pass it down
	certs = &grpc.GrpcSecurity{
		CertFile: path.Join(voltha_base, voltha_cert),
		KeyFile:  path.Join(voltha_base, voltha_key),
		CaFile:   path.Join(voltha_base, voltha_ca),
	}

	// Initialize device with common parameters
	pon := core.PonSimDevice{
		Name:        name,
		ExternalIf:  external_if,
		InternalIf:  internal_if,
		Promiscuous: promiscuous,
		SnapshotLen: snapshot_len,
		Address:     grpc_addr,
		Port:        int32(grpc_port),
		AlarmsOn:    alarm_sim,
		AlarmsFreq:  alarm_freq,
		Counter:     core.NewPonSimMetricCounter(name, device_type),

		// TODO: pass certificates
		//GrpcSecurity: certs,
	}

	switch device_type {
	case core.OLT.String():
		device = core.NewPonSimOltDevice(pon)
		device.(*core.PonSimOltDevice).MaxOnuCount = onus
		device.(*core.PonSimOltDevice).VCoreEndpoint = vcore_endpoint

	case core.ONU.String():
		device = core.NewPonSimOnuDevice(pon)
		device.(*core.PonSimOnuDevice).ParentAddress = parent_addr
		device.(*core.PonSimOnuDevice).ParentPort = int32(parent_port)
		device.(*core.PonSimOnuDevice).SerialNumber = serial_number

	default:
		log.Println("Unknown device type")
	}

	ps := PonSimService{device: device}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ps.Start(ctx)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	doneCh := make(chan struct{})

	go func() {
		for {
			select {
			case <-signals:
				log.Println("Interrupt was detected")
				doneCh <- struct{}{}
			}
		}
	}()

	<-doneCh
}
