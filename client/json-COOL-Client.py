# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.



from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response
import requests

'''
sudo PYTHONPATH=. ./bin/ryu-manager  --enable-debugger --observe-links  --verbose ryu/app/sdnip/topology_management/topo_discover_13.py
'''

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/'

class COOL_Client():

    def __init__(self):
        self.global_table = None

    def get_global_flow_table(self):
        resp_list_prefixes = requests.get('http://localhost:8080/get_global_flow_table/')
        print resp_list_prefixes,resp_list_prefixes.json()
        #print ">>",type(resp_list_prefixes.json())#,"\n\n",resp_list_prefixes,type(resp_list_prefixes)
        self.global_table = resp_list_prefixes.json()
        # for key in self.global_table:
        #     print key,self.global_table[key]
        #print type(self.global_table),"\n",self.global_table

    def create_flow(self, data):
        resp_list_prefixes = requests.put('http://localhost:8080/create_flow/',json.dumps(data))
        print "Finished!",resp_list_prefixes

    def hello_world(self):
        resp_list_prefixes = requests.get('http://localhost:8080/hello_world/')
        print "Finished!",resp_list_prefixes.content

    def enable_BGP(self):
        resp_list_prefixes = requests.get('http://localhost:8080/enable_BGP/')
        print "Finished!",resp_list_prefixes.content

    def northbound_enable_BGP(self):
        resp_list_prefixes = requests.get('http://localhost:8080/northbound/enable_BGP/')
        print "Finished!",resp_list_prefixes.content

if __name__ == '__main__':

    # d = {}
    # json.loads(d)
    #print json.loads(l)
    client = COOL_Client()
    #client.enable_BGP()
    client.hello_world()
    client.northbound_enable_BGP()
    # data = {'ipv4_src':'10.0.0.1', 'ipv4_dst':'10.0.0.100', 'primary_path':[1,4,5,6,3]}
    # data = {'ipv4_src': '10.0.0.1', 'ipv4_dst': '10.0.0.100'}
    # data2 = {'ipv4_src': '10.0.0.100', 'ipv4_dst': '10.0.0.1'}
    # client.create_flow(data)
    # client.create_flow(data2)
    #
    # client.get_global_flow_table()



    # resp_list_prefixes = requests.get('http://localhost:8080/get_global_flow_table/')
    #
    # print resp_list_prefixes.json()
    #
    # resp_list_prefixes = requests.get('http://localhost:8080/get_bandwidth/')
    # # {1: {'10.0.0.4': {'bytes_count': 15440194, 'bandwidth': 0.7827210324773589, 'time': 1506423528.3871},
    # #      '10.0.0.1': {'bytes_count': 15439900, 'bandwidth': 0.7827214050991447, 'time': 1506423528.387116}},
    # #  2: {'10.0.0.4': {'bytes_count': 0,       'bandwidth':                0.0, 'time': 1506423528.386232},
    # #      '10.0.0.1': {'bytes_count': 0,       'bandwidth':                0.0, 'time': 1506423528.386247}},
    # #  3: {'10.0.0.4': {'bytes_count': 15440096, 'bandwidth': 0.7837797764619445, 'time': 1506423528.385328},
    # #      '10.0.0.1': {'bytes_count': 15439998, 'bandwidth': 0.7837794028317826, 'time': 1506423528.385345}},
    # #  4: {'10.0.0.4': {'bytes_count': 15440096, 'bandwidth': 0.7835693856635203, 'time': 1506423528.388472},
    # #      '10.0.0.1': {'bytes_count': 15439900, 'bandwidth': 0.7835745203566283, 'time': 1506423528.388488}}}
    #
    # print resp_list_prefixes.json()
    # #Get list of prefix with bandwidth utilization
    # resp_list_prefixes = requests.get('http://localhost:8080/get_prefixes/')
    # #print resp_list_prefixes.json()
    # prefixes = json.loads(resp_list_prefixes.json()) #transforms JSON format to a Python list of dictionaries
    # print type(prefixes)
    # #print type(json.loads(resp_list_prefixes.json())),json.loads(resp_list_prefixes.json())
    # try:
    #     for prefix in prefixes:
    #         for path in prefixes[prefix]['paths']:
    #             print path['path'],type(path)
    # except ValueError, e:
    #     print "Error!",e
    #
    # data = "{'weight':1,'weight':2}"
    # resp = requests.post('http://localhost:8080/loadbalacing/',json=data)
    # if resp.status_code != 200:
    #     pass
    #     # This means something went wrong.
    #     #raise ApiError('GET /tasks/ {}'.format(resp.status_code))
    # #print resp,resp.json()
    # # for todo_item in resp.json():
    # #     print('{} {}'.format(todo_item['id'], todo_item['summary']))
