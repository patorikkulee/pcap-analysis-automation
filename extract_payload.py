from os import listdir
from os.path import isfile, join
import pandas

protocol = str(input('protocol:'))
dirpath = '/home/patrick/Downloads/' + protocol
files = [f for f in listdir(dirpath) if isfile(join(dirpath, f)) and '.txt' in f and 'metadata' not in f] # get all files in a directory
df = pandas.DataFrame(columns=['Attack pattern ID', 'subcluster ID', 'isp', 'text', 'binary']) # create a new df to store parsed data

clusterSeparator = '==============================\n'
payloadSeparator = '----------------------------\n'

# main function of parsing a file
def main(filename):
    parsed = [] # store parsed data

    with open(dirpath + '/' + filename, 'r', encoding='UTF8') as f:
        subclusters = [l.split(',') for l in ','.join(f.readlines()).split(clusterSeparator) if l.split(',') != ['']] # separate subclusters in file
        
        # remove empty strings from separation process
        for sub in subclusters:
            while '' in sub:
                sub.remove('')
        
        for sub in subclusters:
            subcluster = [l.split(',') for l in ','.join(sub).split(payloadSeparator) if l.split(',') != ['']] # separate payload in subclusters
            
            # remove empty strings from separation process
            for payload in subcluster: 
                while '' in payload:
                    payload.remove('')
            
            parsed.append(subcluster)
    
    global df
    attackpatternid = filename.rstrip('.txt')
    for sub in parsed:
        subclusterid = sub[0][0].lstrip('id: ').rstrip('\n')
        isp = sub[0][1].lstrip('isp: ').rstrip('\n')
        
        for session in sub:
            if 'Attacker to Honeypot\n' in session:
                position = session.index('Attacker to Honeypot\n')
                payload = ''.join(session[position+1:]).lstrip('\n').rstrip('\n').rsplit('\n',1)
                binary = payload[-1]
                text = (None if len(payload)==1 else payload[0])

                row = {'Attack pattern ID': attackpatternid,'subcluster ID': subclusterid, 'isp': isp, 'text': text, 'binary': binary}
                df = df.append(row, ignore_index=True)

if __name__=='__main__':
    for each in files:
        main(each)

    print('df size : ', df.shape)
    df.to_csv(f'payload_{protocol}.csv', index=False) # save .csv file
