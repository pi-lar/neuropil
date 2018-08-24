#!/usr/bin/env bash

tmux=`find /usr -name "tmux" 2>/dev/null | grep "bin" | head -n 1`

echo "Calling tmux via \"${tmux}\""

PWD=`pwd`

echo "prepare enviroment"
${tmux} has-session -t "neuropilDemo"
if [ "$?" -eq 0 ] ; then
  ${tmux} kill-session -t "neuropilDemo"
fi
rm *.log *core*

${tmux} new-session -d -s "neuropilDemo" -n "demo_service"
${tmux} new-window -t "neuropilDemo" -n "raspi1"
${tmux} new-window -t "neuropilDemo" -n "raspi2"

${tmux} send-keys -t "demo_service" "cd  ${PWD}" ENTER
${tmux} send-keys -t "demo_service" "pwd" ENTER

${tmux} send-keys -t "raspi1" "cd  ${PWD}" ENTER
${tmux} send-keys -t "raspi1" "pwd" ENTER

${tmux} send-keys -t "raspi2" "cd  ${PWD}" ENTER
${tmux} send-keys -t "raspi2" "pwd" ENTER


PREFIX=""
POSTFIX=""
#PREFIX="valgrind --log-file=neuropil_%p_callgrind.log "
CALL=${PREFIX}"./bin/neuropil_demo_service -d -3 -s 1 -b 3000 -u localhost"${POSTFIX}
${tmux} send-keys -t "demo_service" "${CALL}" ENTER
sleep 1
CALL=${PREFIX}"./bin/neuropil_raspberry -d -3 -s 1 -b 3001 -u localhost -j *:udp4:localhost:3000 -o 3 -k 1"${POSTFIX}
${tmux} send-keys -t "raspi1"  "${CALL}" ENTER
CALL=${PREFIX}"./bin/neuropil_raspberry -d -3 -s 1 -b 3002 -u localhost -j *:udp4:localhost:3000 -o 3 -k 2"${POSTFIX}
${tmux} send-keys -t "raspi2"  "${CALL}" ENTER

${tmux} a -t "neuropilDemo"
${tmux} select-window -t "demo_service"

 
