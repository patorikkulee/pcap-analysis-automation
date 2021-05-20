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
        session = table.loc[table['session_time'] == timestamp]
        srcip = session['ip_src'].item()
        dstip = session['ip_dst'].item()
        srcport = session['tcp_srcport'].item()
        dstport = session['tcp_dstport'].item()
        timelist = session['session_time_list'].item()
        
        print(f'session IP: {srcip}  -->  {dstip}')
        print(f'source port : {srcport}\ndestination port : {dstport}')
        print('session time list:\n',timelist)
               
        return {'timelist':timelist,'srcip':srcip, 'dstip':dstip, 'srcport':srcport, 'dstport':dstport}
    
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


def getSessionPackets(date:str, isp:str, timestamp:float, sessionInfo:dict):
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
    
    for each in sessionInfo['timelist']:
        selected_logfile.add(matchFileTime(each, logfilenames))
    
    print('session in ', selected_logfile)
    
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
    savefileto = f'{date}_{isp}_{timestamp}.pcap'
    print(f'writing packets to {savefileto} ...')
    
    sessionIP_srcdst = {sessionInfo['srcip'], sessionInfo['dstip']}
    sessionPort_srcdst = {sessionInfo['srcport'], sessionInfo['dstport']}
    for pkt in pkts:
        if pkt.time in sessionInfo['timelist']:
            if {pkt[IP].src, pkt[IP].dst} == sessionIP_srcdst and {pkt[TCP].sport, pkt[TCP].dport} == sessionPort_srcdst:
                wrpcap(savefileto, pkt, append=True)    

            
def main():
    date = input('enter date here: ')
    isp = input('enter isp here:')
    timestamp = float(input('enter session start time here:'))
    
    session_info = getSessionTimeList(date, isp, timestamp)
    getSessionPackets(date, isp, timestamp, session_info)

    
if __name__ == '__main__':
    main()
    print('done')
    