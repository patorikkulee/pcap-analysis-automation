import os, sys, subprocess

# ---get path---
dirpath = sys.argv[1] # 'e.g., /home/patrick/Documents'
logpath = sys.argv[2] # 'e.g., /home/public'

for files in os.listdir(dirpath):
    # ---run snort---
    abspath = f'{dirpath}/{files}'
    command = ['snort', '-c', '/etc/snort/snort.conf', '-r', abspath, '-l', logpath]
    subprocess.run(command)
    
    # ---rename alert file---
    alertfile = logpath + '/' + files + '.com'
    subprocess.run(['mv', logpath + '/alert.full', alertfile])

    # ---rename snort log---
    snortlog = [x for x in os.listdir(logpath) if 'snort.log' in x][0]
    snort = logpath + '/' + files + '.snort'
    subprocess.run(['mv', logpath + '/' + snortlog, snort])

