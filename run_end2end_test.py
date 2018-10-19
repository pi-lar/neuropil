#!/usr/bin/env python
import os
from pprint import pprint
# Prerequisite for a testbed system:
# - tmux
# - clang
# - git
# - virtualenv
# - python3

branch = "develop"      # Define the branch/tag/commit to test
branch = "fb_testbed"

defaults = {"user": "simonklampt",  "build":True, "bin_dir":"bin", "work_dir":"~/neuropil_testbed", "desc":"", "ip":""}
locations = [
    # Add new testbed systems here: 
    dict(defaults,**{"desc":"Ubuntu",    "ip":"192.168.30.200"}),
    dict(defaults,**{"desc":"FreeBSD",   "ip":"192.168.30.201"}),
    #dict(defaults,**{"desc":"OSX",       "ip":"192.168.40.46", "user":"Development"}),
    #dict(defaults,**{"desc":"Raspberry", "ip":"192.168.40.29", "user":"pi-lar"     }),
]

bootstrap_string   = "00a6f648f360112a2360a5613d4d83420da36bc33053ad3b44837ce94e357c61:tcp6:demo.neuropil.io:3141"
bootstrap_string_w = "*:tcp6:demo.neuropil.io:3141"

options_progs = [    
      ("node",  "node"),
      ("hydra", "hydra -n 1"),
      ("cloud", "cloud "),
    ]
options_threads = [
      ("single threaded", "-t 0"),
      ("multi threaded", "-t 3"),
    ]
options_jointype = [
      ("hash",     "-j %(bootstrap_string)s"),
      ("wildcard", "-j %(bootstrap_string_w)s"),
    ]

build_commands = [
    "deactivate",
    "rm -fr {d[work_dir]}",
    "mkdir -p {d[work_dir]}",
    "cd {d[work_dir]}",
    "echo 'WorkDir:'", 
    "pwd",
    "grep '^git.in.pi-lar.net' ~/.ssh/known_hosts || ssh-keyscan git.in.pi-lar.net >> ~/.ssh/known_hosts 2>/dev/null",
    "git clone git@git.in.pi-lar.net:pi-lar/neuropil_lib.git --branch {branch}  --single-branch -q .",
    "virtualenv -p python3 env",
    "source ./env/bin/activate",
    "pip install scons",
    "scons debug=1 test=0"
]

for d in locations: 
    command = []    
    for option_prog_s,option_prog  in options_progs:
        option_prog = option_prog%locals()
        command_desc = "REGISTER_TEST:%(option_prog_s)s"%locals()        
        command_call = "./{d[bin_dir]}/neuropil_{option_prog} -s 0 -u '{d[ip]}'".format(**locals())
        for option_thread_s,option_thread in options_threads:
            command_desc2 = command_desc +" %(option_thread_s)s"%locals()
            command_call2 = command_call +" %s"%(option_thread%locals())
            for option_jointype_s,option_jointype in options_jointype:
                command_desc3 = command_desc + " %(option_jointype_s)s"%locals()
                command_call3 = command_call2+" %s"%(option_jointype%locals())
                command += [command_call3]#+" -m '%s'"%command_desc3]
 

    commands_prefix = ['cd {d[work_dir]}',
        'tmux start-server',        
        'tmux kill-session -t neuropil_E2E_tests',
        'tmux new-session  -d -s neuropil_E2E_tests -n neuropil_E2E_test',
        'tmux set -t neuropil_E2E_tests -g remain-on-exit on',
        ]
    
    if d["build"]:
        commands_prefix = build_commands + commands_prefix
    command_s = ";".join(commands_prefix).format(**locals())+";"
    run_command_s = ""    
    for i, cmd in enumerate(command):
        run_command_s += "tmux new-window -ad -n np_{i} -t neuropil_E2E_test {cmd};".format(**locals())
    
    command_s += run_command_s
    
    cmd = "echo \"{command_s}\" | ssh -A {d[user]}@{d[ip]} ".format(**locals())
    print(cmd)
    result = os.system(cmd)    
    print("Exec on {d[user]}@{d[ip]} = {result}".format(**locals()))
    break