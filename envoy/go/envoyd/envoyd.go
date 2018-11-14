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
package main // import "ciena.com/envoyd"

import (
	"context"
	"os"
	"os/exec"
	"fmt"
	"log"
	"strconv"
	"time"
	"net"
	"io/ioutil"
	"io"
	"text/template"
	"encoding/json"
	"sync"
	"flag"
	"bufio"
	consulapi "github.com/hashicorp/consul/api"
//  etcdapi "github.com/coreos/etcd/clientv3"
	etcdapi "go.etcd.io/etcd/clientv3"
)

// DATA STRUCTURES

//Client provides an interface for getting data out of Consul
type Client interface {
// Get a Service from consulapi
	Service(string, string) ([]string, error)
// Register a service with local agent
	Register(string, int) error
// Deregister a service with local agent
	DeRegister(string) error
}

type client struct {
	consulapi *consulapi.Client
}

type KvConnectFunc func(string, string) (error)
type KvMonitorFunc func()

type EnvoyConfigVars struct {
	VolthaVip string
	VolthaRR []string
	vcorePort string
	HttpPort string
	HttpsPort string
	GrpcPort string
}

type VolthaClusterEntry struct {
	Prefix string
	Id string
	Host string
}

// This struct is not used yet
// TODO: Update the daemon to use this structure to for a
// more object oriented implementation
type EnvoyControl struct {
	// Command line parameters
	assignmentKey string
	envoyConfigTemplate string
	envoyConfigTemplateBoth string
	envoyConfigTemplateNoHttps string
	envoyConfigTemplateNoHttp string
	envoyHttpPort string
	envoyHttpsPort string
	httpDisabled bool
	httpsDisabled bool
	envoyConfig string
	vcoreSvcName  string
	consulSvcName  string
	vcorePort string
	envoyGrpcPort string
	consulPort string
	kvStore string
	kvSvcName string
	kvPort string
	kvConnect map[string]KvConnectFunc
	kvMonitor map[string]KvMonitorFunc
	retries int
	waitTime int
	// Runtime variables
	consul * consulapi.Client
	etcd * etcdapi.Client
	vcoreHostIpName string
	vcoreIdName string
	vc []VolthaClusterEntry
	ipAddrs map[string][]string
	restartEpoch int
	reLock sync.Mutex // Exclusive access to the restartEpoch
}


func NewEnvoyControl() (ec * EnvoyControl) {
	var envCtrl EnvoyControl = EnvoyControl { // Default values
		// Command line parameters
		assignmentKey: "service/voltha/data/core/assignment",
		envoyConfigTemplate: "/envoy/voltha-grpc-proxy.template.json",
		envoyConfigTemplateBoth: "/envoy/voltha-grpc-proxy.template.json",
		envoyConfigTemplateNoHttps: "/envoy/voltha-grpc-proxy-no-https.template.json",
		envoyConfigTemplateNoHttp: "/envoy/voltha-grpc-proxy-no-http.template.json",
		envoyHttpsPort: "8443",
		envoyHttpPort: "8882",
		envoyGrpcPort: "50555",
		httpDisabled: false,
		httpsDisabled: false,
		envoyConfig: "/envoy/voltha-grpc-proxy.json",
		//envoyLogFile: "/envoy/voltha_access_log.log",
		vcoreSvcName: "vcore",
		consulSvcName: "consul",
		vcorePort: "50556",
		consulPort: "8500",
		kvStore: "consul",
		kvSvcName: "consul",
		kvPort: "8500",
		retries: 10,
		waitTime: 2,
		// Runtime variables
		vcoreHostIpName: "host",
		vcoreIdName: "id",
		ipAddrs: make(map[string][]string),
		restartEpoch: 0,
	}
	ec = &envCtrl
	ec.kvConnect = make(map[string]KvConnectFunc)
	ec.kvConnect["consul"] = ec.consulConnect
	ec.kvConnect["etcd"] = ec.etcdConnect
	ec.kvMonitor = make(map[string]KvMonitorFunc)
	ec.kvMonitor["consul"] = ec.monitorConsulKey
	ec.kvMonitor["etcd"] = ec.monitorEtcdKey
	return
}

func (ec * EnvoyControl) resolveServiceAddress(serviceName string) (err error) {
	for i := 0; i < ec.retries; i++ {
		ec.ipAddrs[serviceName], err = net.LookupHost(serviceName)
		if err != nil {
			log.Printf("%s name resolution failed %d time(s) retrying...", serviceName, i+1)
		} else {
			//fmt.Printf("%s address = %s\n",serviceName, addrs[0])
			break
		}
		time.Sleep(time.Duration(ec.waitTime) * time.Second)
	}
	if err != nil {
		log.Printf("%s name resolution failed %d times giving up", serviceName, ec.retries)
	}
	return
}

func (ec * EnvoyControl) consulConnect(serviceName string, port string) (err error) {
	// Fire up a consul client and get the kv store
	cConfig := consulapi.DefaultNonPooledConfig()
	cConfig.Address = ec.ipAddrs[serviceName][0] + ":" + port
	ec.consul, err = consulapi.NewClient(cConfig)
	if err != nil {
		log.Fatal("error creating consul client aborting")
		return
	}
	return
}

func (ec * EnvoyControl) etcdConnect(serviceName string, port string) (err error) {
	// Fire up an etcd client to access the kv store
	cfg := etcdapi.Config {
		Endpoints: []string{serviceName + ":" + port},
		DialTimeout: 5 * time.Second,
	}
	ec.etcd, err = etcdapi.New(cfg)
	if err != nil {
		log.Fatal("Failed to create etcd client, aborting...")
		return
	}
	return
}

//NewConsul returns a Client interface for given consulapi address
func NewConsulClient(addr string) (*client, error) {
	config := consulapi.DefaultConfig()
	config.Address = addr
	c, err := consulapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &client{consulapi: c}, nil
}

// Register a service with consulapi local agent
func (c *client) Register(name string, port int) error {
	reg := &consulapi.AgentServiceRegistration{
		ID:   name,
		Name: name,
		Port: port,
	}
	return c.consulapi.Agent().ServiceRegister(reg)
}

// DeRegister a service with consulapi local agent
func (c *client) DeRegister(id string) error {
	return c.consulapi.Agent().ServiceDeregister(id)
}

// Service return a service
func (c *client) Service(service, tag string) ([]*consulapi.ServiceEntry, *consulapi.QueryMeta, error) {
	passingOnly := true
	addrs, meta, err := c.consulapi.Health().Service(service, tag, passingOnly, nil)
	if len(addrs) == 0 && err == nil {
		return nil, nil, fmt.Errorf("service ( %s ) was not found", service)
	}
	if err != nil {
		return nil, nil, err
	}
	return addrs, meta, nil
}

// Starts envoy with the current restartEpoch
func (ec * EnvoyControl) startEnvoy() {
	var curEpoch int
	var err error
	var count int

	ec.reLock.Lock() // Make sure we've got exclusive access to the variable
	cmd := exec.Command("/usr/local/bin/envoy", "--restart-epoch", strconv.Itoa(ec.restartEpoch),
			    "--config-path", ec.envoyConfig, "--parent-shutdown-time-s", "10")

	curEpoch = ec.restartEpoch
	ec.restartEpoch += 1
	ec.reLock.Unlock() // Done, release the lock.

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatalf("Couldn't attach to stderr running envoy command: %s", err.Error())
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Couldn't attach to stdout running envoy command: %s", err.Error())
	}
	so := bufio.NewReader(stdout)
	se := bufio.NewReader(stderr)

	if err = cmd.Start(); err != nil {
		log.Fatalf("Error starting envoy: %s", err.Error())
	}
	log.Printf("Envoy(%d) started", curEpoch)
	soEof := false
	seEof := false

	data := make([]byte, 80)
	log.Printf("Log forwarding for envoy(%d) started", curEpoch)
	for {
		data = make([]byte, 80)
		count, err = so.Read(data)
		log.Printf("ENVOY_LOG(%d): %s", curEpoch, string(data))
		if err == io.EOF {
			if seEof == true {
				break
			} else {
				soEof = true
			}
		} else if err != nil {
			log.Fatalf("Attempt to read envoy standard out failed: %s", err.Error())
		} else if count > 0 {
			log.Printf("ENVOY_LOG(%d)(%d): %s",curEpoch,count,string(data))
		}
		data = make([]byte, 80)
		count, err = se.Read(data)
		if err == io.EOF {
			if soEof == true {
				break
			} else {
				seEof = true
			}
		} else if err != nil {
			log.Fatalf("Attempt to read envoy standard err failed: %s", err.Error())
		} else if count > 0 {
			log.Printf("ENVOY_LOG(%d)(%d): %s",curEpoch,count,string(data))
		}
	}
	log.Printf("Waiting on envoy %d to exit", curEpoch)
	if err = cmd.Wait(); err != nil {
		log.Fatalf("Envoy %d exited with an unexpected exit code: %s", curEpoch, err.Error())
	}
	log.Printf("Envoy %d exited", curEpoch)
	// Check if this was the primary envoy, if so
	// something went terribly wrong, panic to force
	// forcefully exit.
	ec.reLock.Lock()
	if ec.restartEpoch == (curEpoch + 1) {
		ec.reLock.Unlock()
		log.Fatal("Last running envoy exited, aborting!")
		panic("This should never happen")
	}
	ec.reLock.Unlock()

}

// This function will use the provided templete file to generate
// the targetfile substituting
func (ec * EnvoyControl) updateEnvoyConfig(ecv * EnvoyConfigVars) (err error) {
	var firstRun bool = true
	var firstRun2 bool = true
	f := func() (bool) {
		var rtrn bool = firstRun
		firstRun = false
		return rtrn
	}
	g := func() (bool) {
		var rtrn bool = firstRun2
		firstRun2 = false
		return rtrn
	}
	var funcs = template.FuncMap{"isFirst": f, "isFirst2": g}
	// Slurp up the template file.
	tplt, err := ioutil.ReadFile(ec.envoyConfigTemplate)
	if err != nil {
		log.Fatalf("ERROR reading the template file, aborting: %s", err.Error())
	}
	//fmt.Println(string(tplt))
	configTemplate, err := template.New("config").Funcs(funcs).Parse(string(tplt));
	if err != nil {
		log.Fatalf("Unexpected error loading the Envoy template, aborting: %s", err.Error())
	}
	outFile,err := os.Create(ec.envoyConfig)
	if err != nil {
		log.Fatalf("Unexpected error opening the Envoy config file for write, aborting: %s", err.Error())
	}
	if err = configTemplate.Execute(outFile, ecv); err != nil {
		log.Fatalf("Unexpected error executing the Envoy config template, aborting: %s", err.Error())
	}
	//cfgFile, err := ioutil.ReadFile(ec.envoyConfig)
	//if err != nil {
	//	log.Fatalf("ERROR reading the config file, aborting: %s", err.Error())
	//	panic(err)
	//}
	//fmt.Println(string(cfgFile))
	return
}

func (ec * EnvoyControl) parseAssignment(jsonString []byte) (vCluster []VolthaClusterEntry, err error) {
	var f interface{}
	var vc VolthaClusterEntry
	//var isErr bool

	log.Printf("Parsing %s", string(jsonString))
	//err = json.Unmarshal(jsonString, &f)
	err = json.Unmarshal(jsonString, &f)
	if err != nil {
		log.Fatalf("Unable to parse json record %s : %s", jsonString, err.Error())
	} else {
		m := f.(map[string]interface{})
		for k, v := range m {
			isErr := false
			vc.Prefix = k
			//log.Printf("Processing key %s\n", k)
			switch vv := v.(type) {
			case map[string]interface{}:
				for i, u := range vv {
					//log.Printf("Processing key %sn", i)
					switch uu := u.(type) {
					case string:
						if i == ec.vcoreHostIpName {
							vc.Host = uu
						} else if i == ec.vcoreIdName {
							vc.Id = uu
						} else {
							log.Printf("WARNING: unexpected descriptor,%s", i)
							isErr = true
						}
					default:
						log.Printf("WARNING: unexpected type, ")
						log.Println(i, u)
						isErr = true
					}
				}
			default:
				log.Printf("WARNING: unexpected type, ")
				log.Println(k, v)
				isErr = true
			}
			if ! isErr {
				vCluster = append(vCluster, vc)
			}
		}
	}
	log.Println("Parsing complete")
	return
}

func (ec * EnvoyControl) prepareEnvoyConfig(keyValue []byte, ecv * EnvoyConfigVars) (err error) {
	var vCluster []VolthaClusterEntry

	ecv.HttpPort = ec.envoyHttpPort
	ecv.HttpsPort = ec.envoyHttpsPort
	ecv.GrpcPort = ec.envoyGrpcPort
	ecv.VolthaVip = ec.ipAddrs[ec.vcoreSvcName][0] + ":" + ec.vcorePort

	// Extract all values from the KV record
	// In the future, the values should all be compared to what we currently have
	vCluster, err = ec.parseAssignment(keyValue)
	if err == nil {
		ec.vc = vCluster // For future use to determine if there's been a real change
		//templateValues["VolthaRR"] = []string{}
		ecv.VolthaRR = []string{}
		for i := range vCluster {
			//log.Printf("Processing %s\n", vCluster[i].Host)
			//templateValues["VolthaRR"] = append(templateValues["VolthaRR"].([]string), vCluster[i].Host)
			ecv.VolthaRR = append(ecv.VolthaRR, vCluster[i].Host + ":" + ec.vcorePort)
		}
	} else {
		log.Fatalf("Couldn't parse the KV record %s: %s", string(keyValue), err.Error())
	}
	return
}

func (ec * EnvoyControl) runEnvoy(keyValue []byte) {
	var err error
	var ecv EnvoyConfigVars

	if err = ec.prepareEnvoyConfig(keyValue, &ecv); err != nil {
		log.Fatalf("Error preparing envoy config variables, aborting: %s", err.Error())
	}

	// Now that we have the data loaded, update the envoy config and start envoy
	ec.updateEnvoyConfig(&ecv)
	go ec.startEnvoy()
}

func (ec * EnvoyControl) readConsulKey(key string, qo * consulapi.QueryOptions) (value []byte, meta * consulapi.QueryMeta, err error) {

	var kvp *consulapi.KVPair

	kv := ec.consul.KV()
	// Get the initial values of the assignment key which contains individual
	// voltha core IP addresses. This may be empty until voltha populates it
	// so it must be checked
	kvp, meta, err = kv.Get(ec.assignmentKey, qo)
	for i := 0; i < ec.retries; i++ {
		if err != nil {
			fmt.Println(err)
			log.Printf("Unable to read assignment consul key, retry %d", i+1)
			time.Sleep(time.Duration(ec.waitTime) * time.Second)
			kvp, meta, err = kv.Get(ec.assignmentKey, qo)
		} else if kvp != nil && len(string(kvp.Value)) > 10 {
			// A valid read, return
			value = kvp.Value
			break
		} else {
			log.Printf("Voltha assignment key invalid, retry %d", i+1)
			time.Sleep(time.Duration(ec.waitTime) * time.Second)
			kvp, meta, err = kv.Get(ec.assignmentKey, qo)
		}
		if i == ec.retries {
			log.Fatalf("Failed to read the assignment key after %d retries, aborting: %s", ec.retries, err.Error())
		}
	}
	return
}

func (ec * EnvoyControl) readEtcdKey(key string) (value []byte, index int64, err error) {
	// Get the initial values of the assignment key which contains individual
	// voltha core IP addresses. This may be empty until voltha populates it
	// so it must be checked
	resp, err := ec.etcd.Get(context.Background(), ec.assignmentKey)
	for i := 0; i < ec.retries; i++ {
		if err != nil {
			fmt.Println(err)
			log.Printf("Unable to read assignment etcd key, retry %d", i+1)
			time.Sleep(time.Duration(ec.waitTime) * time.Second)
			resp, err = ec.etcd.Get(context.Background(), ec.assignmentKey)
		} else if resp != nil && len(resp.Kvs) > 0 && len(resp.Kvs[0].Value) > 10 {
			// A valid read, return
			kv := resp.Kvs[0]
			value = kv.Value
			index = kv.ModRevision
			break
		} else {
			log.Printf("Voltha assignment key from etcd invalid, retry %d", i+1)
			time.Sleep(time.Duration(ec.waitTime) * time.Second)
			resp, err = ec.etcd.Get(context.Background(), ec.assignmentKey)
		}
		if i == ec.retries {
			log.Fatalf("Failed to read assignment key from etcd after %d retries, aborting: %s", ec.retries, err.Error())
		}
	}
	return
}

func (ec * EnvoyControl) monitorConsulKey() {
	var err error
	var qo consulapi.QueryOptions

	// Get the initial values of the assignment key which contains individual
	// voltha core IP addresses. This may be empty until voltha populates it
	// so it must be checked
	log.Printf("Monitoring consul key")
	val, meta, err := ec.readConsulKey(ec.assignmentKey, nil)
	log.Printf("Starting Envoy, initial index = %d", meta.LastIndex)
	ec.runEnvoy(val)

	for {
		qo.WaitIndex = meta.LastIndex
		qo.RequireConsistent = true
		//qo.AllowStale = true
		for {
			if qo.WaitIndex != meta.LastIndex {
				break
			}
			val, meta, err = ec.readConsulKey(ec.assignmentKey, &qo)
			if err != nil {
				log.Fatalf("Unable to read assignment consul key: %s\n", err.Error())
			} else {
				log.Println(string(val))
				log.Printf("meta.LastIndex = %d", meta.LastIndex)
			}
		}
		// Fell through, the index has changed thus the key has changed

		log.Printf("Starting Envoy")
		ec.runEnvoy(val)
		log.Printf("meta.LastIndex = %d", meta.LastIndex)
	}
}

func (ec * EnvoyControl) monitorEtcdKey() {
	var err error

	// Get the initial values of the assignment key which contains individual
	// voltha core IP addresses. This may be empty until voltha populates it
	// so it must be checked

	log.Printf("Monitoring etcd key %s", ec.assignmentKey)
	val, index, err := ec.readEtcdKey(ec.assignmentKey)
	if err == nil {
		lastIndex := index
		log.Printf("Starting Envoy, initial index = %d", lastIndex)
		ec.runEnvoy(val)
	}

	rch := ec.etcd.Watch(context.Background(), ec.assignmentKey)
	for resp := range rch {
	    for _, ev := range resp.Events {
	    	val = ev.Kv.Value
	    	log.Printf("%s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
	    	if ev.Type == etcdapi.EventTypePut {
				log.Printf("Starting Envoy")
				ec.runEnvoy(val)
			}
	    }
	}
}

func (ec * EnvoyControl) ParseCommandArguments() {
	flag.StringVar(&(ec.assignmentKey), "assignment-key", ec.assignmentKey,
				"The key for the voltha assignment value in consul")

	flag.StringVar(&( ec.envoyConfigTemplate),"envoy-cfg-template", ec.envoyConfigTemplate,
					"The path to envoy's configuration template")

	flag.StringVar(&( ec.envoyConfigTemplateBoth),"envoy-cfg-template-both", ec.envoyConfigTemplateBoth,
					"The path to envoy's configuration template for both http and https")

	flag.StringVar(&( ec.envoyConfigTemplateNoHttps),"envoy-cfg-template-no-https", ec.envoyConfigTemplateNoHttps,
					"The path to envoy's configuration template with no https")

	flag.StringVar(&( ec.envoyConfigTemplateNoHttp),"envoy-cfg-template-no-http", ec.envoyConfigTemplateNoHttp,
					"The path to envoy's configuration template with no http")

	flag.StringVar(&(ec.envoyConfig), "envoy-config", ec.envoyConfig,
				"The path to envoy's configuration file" )

	flag.StringVar(&(ec.vcoreSvcName), "vcore-svc-name", ec.vcoreSvcName,
				"The service name of the voltha core service")

	flag.StringVar(&(ec.consulSvcName),"consul-svc-nme", ec.consulSvcName,
				"The service name of the consul service")

	flag.StringVar(&(ec.vcorePort), "vcore-port", ec.vcorePort,
				"The port where the vcore's GRPC service can be found")

	flag.StringVar(&(ec.consulPort), "consul-port", ec.consulPort,
				"The port where the consul service api can be found")

	flag.StringVar(&(ec.kvStore), "kv", ec.kvStore,
		"The KV store: consul or etcd")

	flag.StringVar(&(ec.kvSvcName), "kv-svc-name", ec.kvSvcName,
		"The name of the KV store service")

	flag.StringVar(&(ec.kvPort), "kv-port", ec.kvPort,
		"The port where the KV service api can be found")

	flag.StringVar(&(ec.envoyHttpPort), "http-port", ec.envoyHttpPort,
				"The port where the http front-end is served ")

	flag.StringVar(&(ec.envoyHttpsPort), "https-port", ec.envoyHttpsPort,
				"The port where the https front-end is served ")

	flag.StringVar(&(ec.envoyGrpcPort), "grpc-port", ec.envoyGrpcPort,
				"The port where the grpc front-end is served ")

	flag.IntVar(&(ec.retries), "retries", ec.retries,
			"The number of times to retry name lookups and connect requests before failing")

	flag.IntVar(&(ec.waitTime), "wait-time", ec.waitTime,
			"The number of seconds to wait between retries")

	flag.BoolVar(&(ec.httpDisabled), "disable-http", ec.httpDisabled,
			"Disables the http front-end")

	flag.BoolVar(&(ec.httpsDisabled), "disable-https", ec.httpsDisabled,
			"Disables ths https front-end")

	flag.Parse()
}

func (ec * EnvoyControl) Initialize() (err error) {
	// Resolve KV store's virtual ip address
	if err = ec.resolveServiceAddress(ec.kvSvcName); err != nil {
		log.Fatalf("Can't proceed without KV store's vIP address: %s", err.Error())
	}

	// Resolve voltha's virtual ip address
	if err = ec.resolveServiceAddress(ec.vcoreSvcName); err != nil {
		log.Fatalf("Can't proceed without voltha's vIP address: %s", err.Error())
	}

	if err = ec.kvConnect[ec.kvStore](ec.kvSvcName, ec.kvPort); err != nil {
		log.Fatalf("Failed to create KV client, aborting: %s", err.Error())
	}

	if ec.httpDisabled == true && ec.httpsDisabled == true {
		log.Printf("Cowardly refusing to disable both http and https, leaving them both enabled\n")
	} else if ec.httpDisabled == true {
		log.Printf("Diasabling http\n")
		ec.envoyConfigTemplate = ec.envoyConfigTemplateNoHttp
	} else if ec.httpsDisabled == true {
		log.Printf("Diasabling https\n")
		ec.envoyConfigTemplate = ec.envoyConfigTemplateNoHttps
	}

	return
}

func main() {

	var err error
	var ec * EnvoyControl

	ec = NewEnvoyControl()
	ec.ParseCommandArguments()
	if ec.kvStore != "etcd" {
		ec.kvStore = "consul"
	}
	log.Printf("KV-store %s at %s:%s", ec.kvStore, ec.kvSvcName, ec.kvPort)

	if err = ec.Initialize(); err != nil {
		log.Fatalf("Envoy control initialization failed, aborting: %s", err.Error())
	}


	// Start envoy and monitor changes to the KV store to reload
	// consul's config. This never returns unless something crashes.
	ec.kvMonitor[ec.kvStore]()
	log.Fatal("Monitor returned, this shouldn't happen")
}
