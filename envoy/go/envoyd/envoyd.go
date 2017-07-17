package main // import "ciena.com/envoyd"

import (
	"os"
	"os/exec"
	"fmt"
	"log"
	"strconv"
	"time"
	"net"
	"io/ioutil"
	"text/template"
	"encoding/json"
	consulapi "github.com/hashicorp/consul/api"
)

// DATA STRUCTURES

type ConfigVars struct {
	VolthaVip string
	VolthaRR []string
}

type VolthaClusterEntry struct {
	Prefix string
	Id string
	Host string
}

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

// This struct is not used yet
// TODO: Update the daemon to use this structure to for a
// more object oriented implementation
type EnvoyControl struct {
	retrys int
	waitTime int
	cv ConfigVars
	vc []VolthaClusterEntry
	meta * consulapi.QueryMeta
	kvp * consulapi.KVPair
	ipAddrs map[string][]string
}

// CONSTANTS
var assignmentKey string = "service/voltha/data/core/assignment"
var vcoreHostIpName string = "host"
var vcoreIdName string = "id"
var restartEpoch int = 0
var volthaPort string = "50556" // This will be passed inas an option.
var consulPort string = "8500" // This will be passed in as an option.

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
func startEnvoy(cfg_file string) {
	cmd := exec.Command("/usr/local/bin/envoy", "--restart-epoch", strconv.Itoa(restartEpoch),
			    "--config-path", cfg_file)

	curEpoch := restartEpoch
	restartEpoch += 1
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
		panic(err)
	}
	log.Printf("Waiting on envoy %d to exit", curEpoch)
	if err := cmd.Wait(); err != nil {
		log.Fatal(err, "Unexpected exit code")
	}
	log.Printf("Envoy %d exited", curEpoch)

}

// This function will use the provided templete file to generate
// the targetfile substituting 
func updateEnvoyConfig(templateFile string, targetFile string, cv ConfigVars) {
	var firstRun bool = true
	f := func() (bool) {
		var rtrn bool = firstRun
		firstRun = false
		return rtrn
	}
	var funcs = template.FuncMap{"isFirst": f}
	// Slurp up the template file.
	tplt, err := ioutil.ReadFile(templateFile)
	if err != nil {
		panic("ERROR reading the template file, aborting")
	}
	//fmt.Println(string(tplt))
	configTemplate, err := template.New("config").Funcs(funcs).Parse(string(tplt));
	if err != nil {
		panic(err)
	}
	outFile,err := os.Create(targetFile)
	if err != nil {
		panic(err)
	}
	if err := configTemplate.Execute(outFile, cv); err != nil {
		panic(err)
	}
	//cfgFile, err := ioutil.ReadFile(targetFile)
	//if err != nil {
	//	panic("ERROR reading the config file, aborting")
	//}
	//fmt.Println(string(cfgFile))
}

func getServiceAddr(serviceName string, retrys int, waitTime int) (addrs []string, err error) {
	for i := 0; i < retrys; i++ {
		addrs,err = net.LookupHost(serviceName)
		if err != nil {
			log.Printf("%s name resolution failed %d time(s) retrying...\n", serviceName, i+1)
		} else {
			//fmt.Printf("%s address = %s\n",serviceName, addrs[0])
			break
		}
		time.Sleep(time.Duration(waitTime) * time.Second)
	}
	if err != nil {
		log.Printf("%s name resolution failed %d times gving up\n", serviceName, retrys)
	}
	return
}

func parseAssignment(jsonString []byte) (vCluster []VolthaClusterEntry, err error) {
	var vc VolthaClusterEntry
	var f interface{}

	log.Printf("Parsing %s\n", string(jsonString))
	err = json.Unmarshal(jsonString, &f)
	if err != nil {
			log.Fatal("Unable to parse json record %s", jsonString)
			panic(err)
	} else {
		m := f.(map[string]interface{})
		for k, v := range m {
			vc.Prefix = k
			//log.Printf("Processing key %s\n", k)
			switch vv := v.(type) {
			case map[string]interface{}:
				for i, u := range vv {
					//log.Printf("Processing key %s\n", i)
					switch uu := u.(type) {
					case string:
						if i == vcoreHostIpName {
							vc.Host = uu
						} else if i == vcoreIdName {
							vc.Id = uu
						} else {
							log.Printf("WARNING: unexpected descriptor,%s\n", i)
						}
					default:
						log.Printf("WARNING: unexpected type, ")
						log.Println(i, u)
					}
				}
			default:
				log.Printf("WARNING: unexpected type, ")
				log.Println(k, v)
			}
			vCluster = append(vCluster, vc)
		}
	}
	log.Println("Parsing complete")
	return
}

func runEnvoy(meta * consulapi.QueryMeta, kvp * consulapi.KVPair, values * map[string]interface{}, cv ConfigVars,
			  templatePath string, configPath string) {
	var err error
	var vCluster []VolthaClusterEntry

	// Extract all values from the KV record
	vCluster, err = parseAssignment([]byte(kvp.Value))
	if err == nil {
		(*values)["volthaRR"] = []string{}
		for i := range vCluster {
			//log.Printf("Processing %s\n", vCluster[i].Host)
			(*values)["volthaRR"] = append((*values)["volthaRR"].([]string), vCluster[i].Host)
			cv.VolthaRR = append(cv.VolthaRR, vCluster[i].Host + ":" + volthaPort)
		}
	} else {
		log.Fatal("Couldn't parse the KV record %s\n", string(kvp.Value))
		panic(err)
	}

	// Now that we have the data loaded, update the envoy config and start envoy
	updateEnvoyConfig(templatePath, configPath, cv)
	go startEnvoy(configPath)
	log.Printf("meta.LastIndex = %d\n", meta.LastIndex)
}

func runMonitorEnvoy(kv * consulapi.KV, values * map[string]interface{}, cv ConfigVars,
					templatePath string, configPath string) {
	var err error
	var qo consulapi.QueryOptions


	// Get the initial values of the assignment key which contains individual
	// voltha core IP addresses. This may be empty until voltha populates it
	// so it must be checked
	kvp, meta, err := kv.Get(assignmentKey, nil)
	for i := 0; i < 10; i++ {
		if err != nil {
			fmt.Println(err)
			log.Printf("Unable to read assignment consul key, retry %d\n", i+1)
			time.Sleep(time.Duration(2) * time.Second)
			kvp, meta, err = kv.Get(assignmentKey, nil)
		} else if kvp != nil && len(string(kvp.Value)) > 10 {
			log.Printf("Starting Envoy")
			runEnvoy(meta, kvp, values, cv, templatePath, configPath)
			break
		} else {
			log.Printf("Voltha assignment key invalid, retry %d\n", i+1)
			time.Sleep(time.Duration(2) * time.Second)
			kvp, meta, err = kv.Get(assignmentKey, nil)
		}
	}

	for {
		qo.WaitIndex = meta.LastIndex
		for {
			if qo.WaitIndex != meta.LastIndex {
				break
			}
			kvp, meta, err = kv.Get(assignmentKey, &qo)
			if err != nil {
				log.Fatal("Unable to read assignment consul key")
				panic(err)
			} else {
				log.Println(string(kvp.Value))
				log.Printf("meta.LastIndex = %d\n", meta.LastIndex)
			}
		}
		// Fell through, the index has changed thus the key has changed

		runEnvoy(meta, kvp, values, cv, templatePath, configPath)
	}
}

func main() {

	var err error
	var addrs []string
	var cv ConfigVars // Template variables.
	var consul * consulapi.Client
	var values map[string]interface{} // Key values map

	values = make(map[string]interface{})

	// Resolve consul's virtual ip address
	addrs, err = getServiceAddr("consul", 10, 2)
	if err == nil {
		values["consulvip"] = addrs[0]
		log.Printf("Consul's address = %s\n",addrs[0])
	} else {
		log.Fatal("Can't proceed without consul's vIP address")
		panic(err)
	}

	// Resolve voltha's virtual ip address
	addrs,err = getServiceAddr("vcore", 10, 2)
	if err == nil {
		log.Printf("Voltha address = %s\n",addrs[0])
		// Config var for the template
		cv.VolthaVip = addrs[0] + ":" + volthaPort
		values["volthavip"] = addrs[0]
	} else {
		log.Fatal("Can't proceed without voltha's vIP address")
		panic(err)
	}

	// Fire up a consul client and get the kv store
	config := consulapi.DefaultConfig()
	config.Address = values["consulvip"].(string) + ":" + consulPort
	consul, err = consulapi.NewClient(config)
	if err != nil {
		log.Fatal("error creating consul client aborting")
		panic(err)
	}
	kv := consul.KV()

	// Start envoy and monitor changes to the KV store to reload
	// consul's config. This never returns unless somethign crashes.
	runMonitorEnvoy(kv, &values, cv, "/envoy/voltha-grpc-proxy.template.json", "/envoy/voltha-grpc-proxy.json")
}
