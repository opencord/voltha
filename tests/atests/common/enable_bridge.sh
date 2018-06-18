#!/bin/sh +x

echo 'Enable Bridge'
echo 8 > /sys/class/net/ponmgmt/bridge/group_fwd_mask
