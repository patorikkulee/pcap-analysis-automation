import pickle as pk
import pandas as pd
import tarfile
from scapy.all import *


def getSessionTimeList(date:str, isp:str, timestamp:float):
    filepath = '/home/public/CaseStudy/Session Tables/%s/df2_tuples_%s.pkl' % (date, isp)

    # ---open session table---
    print('retrieving session table...')
    with open(filepath, 'rb') as f:
        tab = pk.load(f)
    table = tab[0]

    # ---get session time list---
    try:
        timelist = table.loc[table['session_time'] == timestamp]['session_time_list'].tolist()[0]
        print('session time list:\n',timelist)
        return timelist
    
    except:
        print(f'cannot find session starts at {timestamp} in pcap file')

        
def matchFileTime(timestamp:float, pcapnames:list):
    for index in range(len(pcapnames)):
        pcaptime = int(pcapnames[index].strip('./snort.log.'))
        
        if pcaptime > timestamp:
            if index==0:
                print('the assigned timestamp is not in the range of this pcap file')
                return None
        
            selected = pcapnames[index-1]
            break
        
        selected = pcapnames[index]       
    return selected


def getSessionPackets(date:str, isp:str, timestamp:float, timelist:list):
    gzipname = ('snort.%s' % date.replace('_', '-') if date != '2020_01_12' else 'pcap_%s' % date)
    filepath = '/home/public/CaseStudy/pcap/%s/%s/%s.tar.gz' % (date, isp, gzipname)
    print('unzipping .tar.gz ...')
    tar = tarfile.open(filepath,'r:gz')
    
    # ---sort pcap file name---
    logfilenames = []
    try:
        for logs in tar:
            logfilenames.append(logs.name)
    except:
        pass

    logfilenames.sort()
    logfilenames.remove('.')
    
    # ---matching timestamp with filename---
    selected_logfile = set()
    
    for each in timelist:
        selected_logfile.add(matchFileTime(each, logfilenames))
    
    print('session is in ', selected_logfile)
    
    # ---open selected logfile and read pcap---
    count = 0
    pkts = PacketList()
    
    for logs in tar:
        if logs.name in selected_logfile:
            print('extracting log file...')
            extracted_logfile = tar.extractfile(logs)
            pkts += rdpcap(extracted_logfile)
            count+=1
            if count == len(selected_logfile):
                break
    
    # ---write packets to a new pcap file---
    print('writing packets in session to pcap file...')
    for pkt in pkts:
        if pkt.time in timelist:
            wrpcap(f'{date}_{isp}_{timestamp}.pcap', pkt, append=True)    

            
def main():
    date = input('enter date here: ')
    isp = input('enter isp here:')
    timestamp = float(input('enter session start time here:'))
    
    timelist = getSessionTimeList(date, isp, timestamp)
    getSessionPackets(date, isp, timestamp, timelist)

    
if __name__ == '__main__':
    main()
    print('done')
    