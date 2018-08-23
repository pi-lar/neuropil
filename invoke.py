#!/usr/bin/env bash
tmux start-server
tmux kill-session -t "autostart"
tmux new-session -d -s "autostart" ./invoke.bash
