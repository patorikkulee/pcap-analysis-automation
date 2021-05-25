import os, sys, subprocess, shutil

# ---get path---
dirpath = sys.argv[1] # 'e.g., /home/patrick/Documents'
logpath = sys.argv[2] # 'e.g., /home/public'

for files in os.listdir(dirpath):
    # ---run suricata---
    abspath = f'{dirpath}\{files}'
    command = ['C:\Program Files\Suricata\suricata.exe', '-c', 'C:\Program Files\Suricata\suricata.yaml', '-l', logpath, '-r', abspath]
    subprocess.run(command)
    
    # ---rename eve.json---
    oldjson = logpath + '\\eve.json'
    newjson = logpath + '\\' + files + '.eve.json'
    shutil.move(oldjson, newjson)

    # ---rename fast log---
    oldfastlog = logpath + '\\fast.log'
    newfastlog = logpath + '\\' + files + '.fast.log'
    shutil.move(oldfastlog, newfastlog)
