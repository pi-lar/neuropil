#!/usr/bin/env bash
tmux start-server || true
sleep 1
tmux kill-session -t "autostart" || true
tmux new-session -d -s "autostart" ./invoke.bash
