# Maple OLT Tests

These tests (obviously) assume access to a Maple-based OLT PON system in the test POD.

The tests are grouped into the following categories:

Manual step-by-step provisioning:

* [M1 - Preprovision and Activate OLT](M01_maple_olt_tests_activate_olt.md)
* [M2 - Activate ONU](M02_maple_olt_tests_activate_onu.md)
* [M3 - Manually Install EAPOL Forwarding Flows](M03_maple_olt_tests_eapol_install.md)
* [M4 - Test EAPOL In/Out Forwarding with OLT-OFTEST](M04_maple_olt_tests_eapol_in_out.md)
* [M5 - Manually Install All Forwarding Flows](M05_maple_olt_tests_install_all_flows.md)
* [M6 - Test unicast (Internet) access](M06_maple_olt_tests_unicast.md)
* [M7 - Test IGMP and multicast (Video) streams](M07_maple_olt_tests_multicast.md)

ONOS-base System Test

* [M8 - Reset Manually Added Flows and Launch ONOS](M08_maple_olt_tests_start_onos.md)
* [M9 - Verify RG Authentication Scenario](M09_maple_olt_tests_verify_authentication.md)
* [M10 - Verify DHCP Lookup](M10_maple_olt_tests_verify_dhcp.md)
* [M11 - Verify Unicast Access](M11_maple_olt_tests_verify_unicast.md)
* [M12 - Verify Multicast Access](M12_maple_olt_tests_verify_multicast.md)

Spirent-base Functional Traffic Tests

* [M13 - Spirent - Verify Re-Write C-VID Upstream](M13_maple_olt_tests_verify_cvid_upstream.md)
* [M14 - Spirent - Verify Re-Write C-VID Downstream](M14_maple_olt_tests_verify_cvid_downstream.md)
* [M15 - Spirent - Verify 802.1ad (QinQ) Upstream](M15_maple_olt_tests_verify_qinq_upstream.md)
* [M16 - Spirent - Verify 802.1ad (QinQ) Downstream](M16_maple_olt_tests_verify_qinq_downstream.md)
* [M17 - Spirent - Verify IPv4 Unicast Streams Downstream](M17_maple_olt_tests_verify_ipv4_downstream.md)
* [M18 - Spirent - Verify IPv4 Unicast Streams Downstream Case2](M18_maple_olt_tests_verify_ipv4_downstream_case2.md)

Miscellaneous Randing Tests

* [M19 - 10k and 20k ONU Ranging](M19_maple_olt_tests_ranging.md)
* [M20 - MIB Download and Upload](M20_maple_olt_tests_mib.md)
* [M21 - 2000 byte Frames](M21_maple_olt_tests_2000_byte_frames.md)
* [M22 - Simultaneous Data and Video Streams](M22_maple_olt_tests_data_and_video.md)
* [M23 - Overnight Traffic Test](M23_maple_olt_tests_overnight.md)

Robustness Testing

* [M24 - Traffic Recovers After Fiber Disconnect (Best Effort)](M24_maple_olt_tests_ha_fiber_disconnect.md)
* [M25 - Traffic Recovers After ONU Reset (Best Effort)](M25_maple_olt_tests_ha_onu_reset.md)
* [M26 - Traffic Recovers After OLT Reset (Best Effort)](M26_maple_olt_tests_ha_olt_reset.md)
* [M27 - Traffic Recovers After ToR Switch Reset (Best Effort)](M27_maple_olt_tests_ha_tor_switch_reset.md)
