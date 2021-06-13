import pickle as pk
import pandas as pd
import datetime
from collections import Counter


def tables_to_open(sessions):
    '''returns a set of tables to be open'''
    tables = set()
    for each in sessions:
        tables.add(each[:2])
        
    return tables

def create_df(sessions):    
    df = pd.DataFrame() # store session info
    tables = tables_to_open(sessions)

    for tab in tables:
        filepath = f'/home/public/CaseStudy/Session Tables/{tab[0]}/df2_tuples_{tab[1]}.pkl'
        timelist = []
        for each in sessions:
            if each[:2]==tab:
                timelist += each[3]
                
        try:
            with open (filepath,'rb') as f:
                print(f'loading session table ...')
                tab = pk.load(f)
                table = tab[0]
        
                for timestamp in timelist:
                    row = table.loc[table['session_time']==timestamp]
                    if row.shape[0]==1:
                        df = df.append(row, ignore_index=True)
                    else:
                        print('timestamp not found in table')
        
        except FileNotFoundError:
            print(f'{filepath} does not exist')
                    
    return df

def get_df_info(df):
    info = {}
    start = min([x for x in df['session_time'].tolist()])
    info['start'] = str(datetime.datetime.fromtimestamp(int(start)))
    end = max([x for x in df.apply(lambda row : row.session_time_list[-1], axis=1).tolist()])
    info['end'] = str(datetime.datetime.fromtimestamp(int(end)))
    info['total_pkt_num'] = sum([len(x)for x in df['session_time_list']])
    info['ipsrc'] = Counter(df['ip_src'].tolist())
    # info['ipdst'] = Counter(df['ip_dst'].tolist())
    info['country'] = Counter(df['country'].tolist())
    return info

result = ''
def print_to_text(x):
    global result
    result += str(x) + '\n'
    
def print_data(sessions):
    print_to_text("- 相關 idx：")
    for each in sessions:
        print_to_text(f'\t- {each[2]}')
    
    df = create_df(sessions)
    info = get_df_info(df)
    
    print_to_text("- 起始時間：")
    print_to_text(f'\t- {info["start"]}')
    
    print_to_text("- 結束時間：")
    print_to_text(f'\t- {info["end"]}')
        
    print_to_text(f"- Session 數量：{sum([len(x[3]) for x in sessions])}" )
    print_to_text(f"- 封包總數：{info['total_pkt_num']}")
    print_to_text(f"- ISP：{', '.join(set([x[1] for x in sessions]))}")
    
    print_to_text("- IP資訊：")
    sum_ipsrc = sum(info['ipsrc'].values())
    for k, v in info['ipsrc'].items():
        print_to_text(f'\t- {k} : {v} ({v/sum_ipsrc*100:.2f}%)')
        
    print_to_text("- 國家資訊：")
    sum_country = sum(info['country'].values())
    for k, v in info['country'].items():
        print_to_text(f'\t- {k} : {v} ({v/sum_country*100:.2f}%)')
        
    print_to_text("- ISP每日資訊：")
    
    isp_daily = dict()
    for each in sessions:
        date_isp = f'{each[0]}_{each[1]}'
        if date_isp in isp_daily:
            isp_daily[date_isp] += len(each[3])
        else:
            isp_daily[date_isp] = len(each[3])
    
    for key in isp_daily:
        print_to_text(f'\t- {key} : {isp_daily[key]}')

def main(sessions, name):
    print_data(sessions)
    global result
    with open(f'{name}_metadata.txt','w') as f:
        f.write(result)
        f.close()
    result = ''


if __name__ == '__main__':    
    # default input : [(date, isp, idx, [timelist]), ...]
    # call main function : main(list of tuple, 'filename')
    given = []
    main(given, 'test_final')
    