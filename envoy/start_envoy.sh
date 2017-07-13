#!/bin/bash

RESTART_EPOCH=0


echo "Staring envoy re-starter"


function fork_envoy()
{
    echo "Forking envoy"
    /usr/local/bin/envoy -l debug -c envoy/front-proxy/voltha-grpc-proxy.json --restart-epoch $RESTART_EPOCH &
    CUR_PID=$!
    RESTART_EPOCH=`expr $RESTART_EPOCH + 1`
    wait
}

function end_envoy()
{
        echo "Killing envoy"
	kill -KILL $CUR_PID
}

trap fork_envoy SIGHUP
trap end_envoy SIGTERM

fork_envoy


