# Copyright 2019-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


#copied from voltha confluence
#https://wiki.opencord.org/display/CORD/Technology+Profile+Instance


tech_profile_json = {
  "name": "4QueueHybridProfileMap1-instance-1",
  "profile Type": "XPON-Instance",
  "version": 1,
  "instance_control": {
    "onu": "multi-instance",
    "uni": "single-instance",
    "num_gem_ports": 4
  },
  "alloc-id": 1024,
  "DBA-Extended-Mode": "disable",
  "u_s_DBA_traffic_descripter": {
    "Fixed-bw": 0,
    "Assured-bw": 0,
    "Max-bw": 0,
    "Additional-bw-eligibility": "best_effort"
  },
  "us_scheduler": {
    "additional_bw": "auto",
    "priority": 0,
    "weight": 0,
    "q_sched_policy": "hybrid"
  },
  "d_s_traffic_descripter": {
    "CIR": 0,
    "CBS": 0,
    "EIR": 0,
    "EBS": 0
  },
  "d_s_scheduler": {
    "priority": 0,
    "weight": 0,
    "q_sched_policy": "hybrid"
  },
  "upstream_gem_port_attribute_list": [
    {
      "gemport_id": 1024,
      "pbit_map": "0b00000101",
      "aes_encryption": "TRUE",
      "scheduling_policy": "WRR",
      "priority_q": 4,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_Traffic_Descriptor": "disable",
      "u_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    },
    {
      "gemport_id": 1025,
      "pbit_map": "0b00011010",
      "aes_encryption": "TRUE",
      "scheduling_policy": "WRR",
      "priority_q": 3,
      "weight": 75,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_U_S_Traffic_Descriptor": "disable",
      "u_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    },
    {
      "gemport_id": 1026,
      "pbit_map": "0b00100000",
      "aes_encryption": "TRUE",
      "scheduling_policy": "StrictPriority",
      "priority_q": 2,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_U_S_Traffic_Descriptor": "disable",
      "u_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    },
    {
      "gemport_id": 1027,
      "pbit_map": "0b11000000",
      "aes_encryption": "TRUE",
      "scheduling_policy": "StrictPriority",
      "priority_q": 1,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_U_S_Traffic_Descriptor": "disable",
      "u_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    }
  ],
  "downstream_gem_port_attribute_list": [
    {
      "gemport_id": 1024,
      "pbit_map": "0b00000101",
      "aes_encryption": "TRUE",
      "scheduling_policy": "WRR",
      "priority_q": 4,
      "weight": 10,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_D_S_Traffic_Descriptor": "disable",
      "d_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    },
    {
      "gemport_id": 1025,
      "pbit_map": "0b00011010",
      "aes_encryption": "TRUE",
      "scheduling_policy": "WRR",
      "priority_q": 3,
      "weight": 90,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_D_S_Traffic_Descriptor": "disable",
      "d_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    },
    {
      "gemport_id": 1026,
      "pbit_map": "0b00100000",
      "aes_encryption": "TRUE",
      "scheduling_policy": "StrictPriority",
      "priority_q": 2,
      "weight": 0,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_D_S_Traffic_Descriptor": "disable",
      "d_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    },
    {
      "gemport_id": 1027,
      "pbit_map": "0b11000000",
      "aes_encryption": "TRUE",
      "scheduling_policy": "StrictPriority",
      "priority_q": 1,
      "weight": 25,
      "discard_policy": "TailDrop",
      "max_q_size": "auto",
      "discard_config": {
        "min_threshold": 0,
        "max_threshold": 0,
        "max_probability": 0
      },
      "GEM_D_S_Traffic_Descriptor": "disable",
      "d_s_traffic_descripter": {
        "CIR": 0,
        "CBS": 0,
        "EIR": 0,
        "EBS": 0
      }
    }
  ]
}

