# Technology Profile Management
## Overview
Technology profiles that are utilized by VOLTHA are stored in a prescribed structure in VOLTHA's key/value store, which is currently etcd. The key structure used to access technology profiles is /voltha/technology_profiles/<TECHNOLOGY>/<TID>; where TID is the numeric ID of the technology profile and TECHNOLOGY specifies the technology being utilized by the adapter, e.g. xgspon. While the TID key is a directory, the TECHNOLOGY key should be set to the JSON data that represents the technology profile values.



`NOTE`: The content of a technology profile represents a contract between the technology profile definition and all adapters that consume that technology profile. The structure and content of the profiles are outside the scope of Technology Profile Management. Technology profile management only specifies the key/value structure in which profiles are stored.

### Example:
```sh
/xgspon/64  {
  "name": "4QueueHybridProfileMap1",
  "profile_type": "XPON",
  "version": 1,
  "num_gem_ports": 4,
  "instance_control": {
    "onu": "multi-instance",
    "uni": "single-instance",
    "max_gem_payload_size": "auto"
  },
  "us_scheduler": {
    "additional_bw": "auto",
    "direction": "UPSTREAM",
    "priority": 0,
    "weight": 0,
    "q_sched_policy": "hybrid"
  },
  "ds_scheduler": {
    "additional_bw": "auto",
    "direction": "DOWNSTREAM",
    "priority": 0,
    "weight": 0,
    "q_sched_policy": "hybrid"
  },
  "upstream_gem_port_attribute_list": [
    {
      "pbit_map": "0b00000101",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 4,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "max_threshold": 0,
        "min_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00011010",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 3,
      "weight": 75,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00100000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 2,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b11000000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 1,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    }
  ],
  "downstream_gem_port_attribute_list": [
    {
      "pbit_map": "0b00000101",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 4,
      "weight": 10,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00011010",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 3,
      "weight": 90,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00100000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 2,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b11000000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 1,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    }
  ]
}
```

## Creating Technology Profiles
Technology profiles are a simple JSON object. This JSON object can be created using a variety of tools such as Vim, Emacs, or various IDEs. JQ can be a useful tool for validating a JSON object. Once a file is created with the JSON object it can be stored in VOLTHA key/value store using the standard etcd command line tool etcdctl or using an HTTP POST operation using Curl.

Assuming you are in a standard VOLTHA deployment within a Kubernetes cluster you can access the etcd key/value store using kubectl via the PODs named etcd-cluster-0000, etcd-cluster-0001, or etcd-cluster-0002. For the examples in this document etcd-cluster-0000 will be used, but it really shouldn't matter which is used.



Assuming the Technology template is stored in a local file 4QueueHybridProfileMap1.json the following commands could be used to `store` or `update` the technical template into the proper location in the etcd key/value store:
```sh
# Store a Technology template using etcdctl
jq -c . 4QueueHybridProfileMap1.json | kubectl exec -i etcd-cluster-0000 -- etcdctl set /xgspon/64

# Store a Technology template using curl
curl -sSL -XPUT http://10.233.53.161:2379/v2/keys/xgspon/64 -d value="$(jq -c . 4QueueHybridProfileMap1.json)"
```

In the examples above, the command jq is used. This command can be installed using standard package management tools on most Linux systems. In the examples the "-c" option is used to compress the JSON. Using this tool is not necessary, and if you choose not to use the tool, you can replace "jq -c ," in the above examples with the "cat" command. More on jq can be found at https://stedolan.github.io/jq/.



## Listing Technical Profiles for a given Technology
While both curl and etcdctl (via kubectl) can be used to list or view the available Technology profiles, etcdctl is easier, and thus will be used in the examples. For listing Technology profiles etcdctl ls is used. In can be used in conjunction with the -r option to recursively list profiles.
```sh
# List all the Technology profiles for a Technology
kubectl exec -i etcd-cluster-0000 -- etcdctl ls /xgspon

# Example output
/xgspon/64
/xgspon/65
```

A specified Technology profile can be viewed with the etcdctl get command. (Again, jq is used for presentation purposes, and is not required)
```sh
# Display a specified Technology profile, using jq to pretty print
kubectl exec -i etcd-cluster-0000 -- etcdctl get /xgspon/64 | jq .

# Example outpout
{
  "name": "4QueueHybridProfileMap1",
  "profile_type": "XPON",
  "version": 1,
  "num_gem_ports": 4,
  "instance_control": {
    "onu": "multi-instance",
    "uni": "single-instance",
    "max_gem_payload_size": "auto"
  },
  "us_scheduler": {
    "additional_bw": "auto",
    "direction": "UPSTREAM",
    "priority": 0,
    "weight": 0,
    "q_sched_policy": "hybrid"
  },
  "ds_scheduler": {
    "additional_bw": "auto",
    "direction": "DOWNSTREAM",
    "priority": 0,
    "weight": 0,
    "q_sched_policy": "hybrid"
  },
  "upstream_gem_port_attribute_list": [
    {
      "pbit_map": "0b00000101",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 4,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "max_threshold": 0,
        "min_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00011010",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 3,
      "weight": 75,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00100000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 2,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b11000000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 1,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    }
  ],
  "downstream_gem_port_attribute_list": [
    {
      "pbit_map": "0b00000101",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 4,
      "weight": 10,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00011010",
      "aes_encryption": "True",
      "scheduling_policy": "WRR",
      "priority_q": 3,
      "weight": 90,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b00100000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 2,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    },
    {
      "pbit_map": "0b11000000",
      "aes_encryption": "True",
      "scheduling_policy": "StrictPriority",
      "priority_q": 1,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      }
    }
  ]
}
```

## Deleting Technology Profiles
A technology profile or a technology profile tree can be removed using etcdctl rm.

```sh
# Remove a specific technology profile
kubectl exec -i etcd-cluster-0000 -- etcdctl rm /xgspon/64

# Remove all technology profiles associated with Technology xgspon and ID 64(including the profile ID key)
kubectl exec -i etcd-cluster-0000 -- etcdctl rm --dir -r /xgspon/64
```

## Reference
https://wiki.opencord.org/display/CORD/Technology+Profile+Management

