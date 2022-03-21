from operator import attrgetter
from statistics import median, fmean
from typing import List
import matplotlib.pyplot as plt
import requests
import re
from pprint import pprint 
import json
import datetime
import pytz
import itertools
import argparse
from time import sleep

# push msg log into grafana-loki
host = 'http://loki.in.pi-lar.net:3100'

latest_build = requests.get(f'{host}/loki/api/v1/label/build/values', headers={'Content-type': 'application/json'}).json()['data'][-1]




parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('build', type=str, default=None, nargs='?', help='build identifier')
parser.add_argument('--last_hours', type=int, default=0)
parser.add_argument('--follow', action='store_true')
args = parser.parse_args()

build = args.build if args.build else latest_build

print(f"checking {build=}")

begin = (datetime.datetime.now(tz=pytz.UTC) - datetime.timedelta(hours=args.last_hours)) if args.last_hours else datetime.datetime.fromisoformat(build)
# truncate microseconds
begin = datetime.datetime.fromtimestamp(int(begin.timestamp()),tz=begin.tzinfo)
initial_begin = begin
end =  datetime.datetime.now(tz=begin.tzinfo)-datetime.timedelta(seconds=10)


#waves = requests.get(f'{host}/loki/api/v1/label/topic/values',params={"start":begin.timestamp()}, headers={'Content-type': 'application/json'}).json()['data']
#pprint(waves)


msg_id_detector = re.compile(r': (?P<msg_id>[a-z0-9.-]{36})')

def query(m, start:float=None, stop:datetime.datetime=None, interval=datetime.timedelta(minutes=10)):
    _params = {
        "query": f'{{build="{build}"}} {m}',
    }

    if start:
        _start = datetime.datetime.fromtimestamp(start,tz=begin.tzinfo)
        _params['start'] = _start.timestamp()
        if stop and (_start + interval) > stop:
            _end = _params['end'] =    stop.timestamp()
        else:
            _end = _params['end'] = (_start + interval).timestamp()

    try:
        result = requests.get(f'{host}/loki/api/v1/query_range', headers={'Content-type': 'application/json'}, params=_params)
    except:
        sleep(60)
        result = requests.get(f'{host}/loki/api/v1/query_range', headers={'Content-type': 'application/json'}, params=_params)

    #pprint(result.text)    
    res = result.json()
    #pprint(res)
    #exit(0)
    yield res['data']['result']
    if start and stop and _start < stop:
        yield from query(m, _end, stop, interval)

result_written = False
class StatisticsEntry():
    def __init__(self) -> None:        
        self.ts = 0
        self.is_found = False
        self.travel_time =0
        self.over_received_count = False
class Statistics():
    def __init__(self) -> None:        
        self.statistic_entries: List[StatisticsEntry] = []

    def print(self):
        if len(self.statistic_entries) == 0:
            print("no msgs found",end="")
        else:
            total = len(self.statistic_entries)
            notfound = len(list(filter(lambda k: not k.is_found, self.statistic_entries)))
            print(f"checked {total} e2e msgs,",end="")
            print(f" {notfound} ({((notfound/total)*100):.0f}%) not found,",end="")
            if total - notfound > 0:
                over_received_list = list(filter(lambda k: k.over_received_count > 0, self.statistic_entries))
                over_received = len(over_received_list)
                over_received_total = sum(j.over_received_count for j in over_received_list)
                ms_max = max(j.travel_time for j in self.statistic_entries)
                ms_min = min(j.travel_time for j in filter(lambda k: k.is_found, self.statistic_entries))
                ms_mean = fmean(j.travel_time for j in filter(lambda k: k.is_found, self.statistic_entries))
                ms_median = median(j.travel_time for j in filter(lambda k: k.is_found, self.statistic_entries))

                print(f" over received {over_received} ({(over_received/total)*100:.0f}%) msgs (with a total of {over_received_total} dupplicate msgs),",end="")
                print(f" max: {ms_max:9.3f}ms",end="")
                print(f" avg: {ms_mean:9.3f}ms",end="")
                print(f" median: {ms_median:9.3f}ms",end="")
                print(f" min: {ms_min:9.3f}ms",end="")
            print("",end="",flush=True)
statistics_sum = Statistics()
statistics_container = {}
def clear_result():
    global result_written
    if result_written:
        print( "\r",end="")
        result_written = False

def exportPlot(detailed=False):
    if detailed:
        fig = plt.figure(figsize=(18*3, 6*3), dpi=600)
    else:
        fig = plt.figure(figsize=(18, 6), dpi=200)
    
    plt.ylabel("ms")
    #plt.yscale('log')
    plt.xticks(rotation=45)
    plt.subplots_adjust(bottom=0.16)

    statistics_sum.statistic_entries.sort(key=attrgetter("ts"))
    # plt.plot(
    #     [ datetime.datetime.fromtimestamp(j.ts / 1000000000) for j in filter(lambda k: k.is_found, statistics_sum.statistic_entries)],
    #     [min(2000,j.travel_time) for j in filter(lambda k: k.is_found, statistics_sum.statistic_entries)]
    #     , label="SUM"
    # ) 
    keys = list(statistics_container.keys())
    i = len(keys)+1
    keys.sort()
    for key in keys:
        values = statistics_container[key]
        values.statistic_entries.sort(key=attrgetter("ts"))
  
        plt.plot(
            [ datetime.datetime.fromtimestamp(j.ts / 1000000000) for j in values.statistic_entries],
            [ (min(2000,j.travel_time)  if j.is_found else ((int(j.is_found) - 1) * 100*i))  for j in values.statistic_entries]
            , label=f"{key}"
        )
        i -= 1
    
    plt.legend(loc="upper left")
    fig.savefig(f'build/{build}.png')
    plt.close('all')

_result_next_plot = datetime.datetime.now()
def result():
    clear_result()
    global result_written, _result_next_plot
    result_written = True
    statistics_sum.print()
    if _result_next_plot < datetime.datetime.now() :
        exportPlot()
        _result_next_plot = datetime.datetime.now()+ datetime.timedelta(seconds=10)
try:
    once = True
    while once or args.follow:
        once = False
        for query_results in query('|="sending message (size"',begin.timestamp(),end):
            for q in query_results:
                stream = q['stream']
                values = q['values']
                if stream['topic'] not in statistics_container:
                    statistics_container[stream['topic']] = Statistics()
                stat = statistics_container[stream['topic']]
                for ts, msg in values:
                    entry = StatisticsEntry()
                    ts = float(ts)
                    entry.ts = ts

                    msg_id = msg_id_detector.findall(msg)[0]
                    prefix = f'{datetime.datetime.fromtimestamp(ts/1000000000).isoformat("T").replace("T"," ")} {{build="{build}"}}|="{msg_id}"'
                    

                    for msg_query_results in query(f'|= "decrypt result for message({msg_id}) from"', start=ts/1000000000, interval=datetime.timedelta(seconds=10)):
                        for msg_query_result in msg_query_results:
                            for msg_query_result_values in msg_query_result['values']:                                
                                if not entry.is_found:
                                    entry.is_found = True
                                    ts2 = msg_query_result_values[0]
                                    msg2 = str(msg_query_result_values[1])
                                    ms = (float(ts2) - ts) / 1000000
                                    entry.travel_time = ms
                                else:
                                    entry.over_received_count += 1                                
                    clear_result()
                    if not entry.is_found:
                        print(f'{prefix} NOT found msg'+60*" ")
                    else:
                        print(f"{prefix}     found msg travel time: {entry.travel_time:8.3f} ms"+30*" ")

                    stat.statistic_entries.append(entry)
                    statistics_sum.statistic_entries.append(entry)

                    result()
        if args.follow:
            begin = end+datetime.timedelta(seconds=1)
            sleep(20)
            end = datetime.datetime.now(tz=begin.tzinfo)-datetime.timedelta(seconds=10)

except KeyboardInterrupt:
    pass

clear_result()
print(f"\n{begin.isoformat('T')} - {end.isoformat('T')}   Range: {end - initial_begin} ")
result()
print("\nrendering plot")
exportPlot()
print(f"done. Export can be found at: build/{build}.png")