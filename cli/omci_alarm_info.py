#
# Copyright 2018 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

_alarm_info = {
    5: {
        'name': 'CardHolder',
        0: 'Plug-in circuit pack missing',
        1: 'Plug-in type mismatch alarm',
        2: 'Improper card removal',
        3: 'Plug-in equipment ID mismatch alarm',
        4: 'Protection switch',
    },
    6: {
        'name': 'CircuitPack',
        0: 'Equipment alarm',
        1: 'Powering alarm',
        2: 'Self-test failure',
        3: 'Laser end of life',
        4: 'Temperature yellow',
        5: 'Temperature red',

    },
    11: {
        'name': 'PptpEthernetUni',
        0: 'LAN Loss Of Signal',
    },
    47: {
        'name': 'MacBridgePortConfigurationData',
        0: 'Port blocking',
    },
    256: {
        'name': 'OntG',
        0: 'Equipment alarm',
        1: 'Powering alarm',
        2: 'Battery missing',
        3: 'Battery failure',
        4: 'Battery low',
        5: 'Physical intrusion',
        6: 'Self-test failure',
        7: 'Dying gasp',
        8: 'Temperature yellow',
        9: 'Temperature red',
        10: 'Voltage yellow',
        11: 'Voltage red',
        12: 'ONU manual power off',
        13: 'Invalid image',
        14: 'PSE overload yellow',
        15: 'PSE overload red',
    },
    263: {
        'name': 'AniG',
        0: 'Low received optical power',
        1: 'High received optical power',
        2: 'Signal fail',
        3: 'Signal degrade',
        4: 'Low transmit optical power',
        5: 'High transmit optical power',
        6: 'Laser bias current',
    },
    266: {
        'name': 'GemInterworkingTp',
        6: 'Operational state change',
    },
    268: {
        'name': 'GemPortNetworkCtp',
        5: 'End-to-end loss of continuity',
    },
    277: {
        'name': 'PriorityQueueG',
        0: 'Block loss',
    },
    281: {
        'name': 'MulticastGemInterworkingTp',
        0: 'Deprecated',
    },
    309: {
        'name': 'MulticastOperationsProfile',
        0: 'Lost multicast group',
    },
    329: {
        'name': 'VirtualEthernetInterfacePt',
        0: 'Connecting function fail',
    },
    24: {
        'name': 'EthernetPMMonitoringHistoryData',
        0: 'FCS errors',
        1: 'Excessive collision counter',
        2: 'Late collision counter',
        3: 'Frames too long',
        4: 'Buffer overflows on receive',
        5: 'Buffer overflows on transmit',
        6: 'Single collision frame counter',
        7: 'Multiple collision frame counter',
        8: 'SQE counter',
        9: 'Deferred transmission counter',
        10: 'Internal MAC transmit error counter',
        11: 'Carrier sense error counter',
        12: 'Alignment error counter',
        13: 'Internal MAC receive error counter',
    },
    312: {
        'name': 'FecPerformanceMonitoringHistoryData',
        0: 'Corrected bytes',
        1: 'Corrected code words',
        2: 'Uncorrectable code words',
        4: 'FEC seconds',
    },
    321: {
        'name': 'EthernetFrameDownstreamPerformanceMonitoringHistoryData',
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    },
    322: {
        'name': 'EthernetFrameUpstreamPerformanceMonitoringHistoryData',
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    },
    329: {
        'name': 'VeipUni',
        0: 'Connecting function fail'
    },
    334: {
        'name': 'EthernetFrameExtendedPerformanceMonitoring',
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    },
    426: {
        'name': 'EthernetFrameExtendedPerformanceMonitoring64Bit',
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    },
    341: {
        'name': 'GemPortNetworkCtpMonitoringHistoryData',
        1: 'Encryption key errors',
    },
    344: {
        'name': 'XgPonTcPerformanceMonitoringHistoryData',
        1: 'PSBd HEC error count',
        2: 'XGTC HEC error count',
        3: 'Unknown profile count',
        4: 'XGEM HEC loss count',
        5: 'XGEM key errors',
        6: 'XGEM HEC error count',
    },
    345: {
        'name': 'anceMonitoringHistoryData',
        1: 'PLOAM MIC error count',
        2: 'OMCI MIC error count',
    },
}

