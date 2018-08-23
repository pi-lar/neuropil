#!/usr/bin/env bash
tmux start-server || true
tmux kill-session -t "autostart" || true
tmux new-session -d -s "autostart" ./invoke.bash
