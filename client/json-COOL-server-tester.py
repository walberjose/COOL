# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
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

# Generate the graph topology
import networkx as nx

#Manipulate IP addresses
from netaddr import *

from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import lldp
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto as inet
from ryu.ofproto import ofproto_v1_3
# Below is the library used for topo discovery
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

#COOL administration
from ryu.app.COOL.Interfaces.cool_interface import COOL_Interface
from ryu.app.COOL.flow_management.flow_management import FlowManagement
from ryu.app.COOL.topology_management.topology_management import TopologyManagement
from ryu.app.COOL.domain_controller.network_administration import Network_Administration

# Enable multithread in Ryu (Eventle)
# Utils
# from ryu.app.sdnip.sdnip_utils.packets_utils import packets_handler
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response

simple_switch_instance_name = 'cool_interface'
url = '/simpleswitch/'

class COOL_Interface(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(COOL_Interface, self).__init__(req, link, data, **config)
        self.get_global_flow_table =   {(3, '10.0.0.1', '10.0.0.100'): {'group_id': 0, 'instructions': {(1, 2): {'in_port': 1, 'out_port': 2}, 'primary_path': [1, 2, 3], (2, 3): {'in_port': 1, 'out_port': 2}, (3, '10.0.0.100'): {'in_port': 2, 'out_port': 1}, 'backup_path': None}}, (3, '10.0.0.100', '10.0.0.1'): {'group_id': 0, 'instructions': {'primary_path': [3, 2, 1], (3, 2): {'in_port': 1, 'out_port': 2}, (2, 1): {'in_port': 2, 'out_port': 1}, (1, '10.0.0.1'): {'in_port': 2, 'out_port': 1}, 'backup_path': None}}, (2, '10.0.0.100', '10.0.0.1'): {'group_id': 0, 'instructions': {'primary_path': [3, 2, 1], (3, 2): {'in_port': 1, 'out_port': 2}, (2, 1): {'in_port': 2, 'out_port': 1}, (1, '10.0.0.1'): {'in_port': 2, 'out_port': 1}, 'backup_path': None}}, (2, '10.0.0.1', '10.0.0.100'): {'group_id': 0, 'instructions': {(1, 2): {'in_port': 1, 'out_port': 2}, 'primary_path': [1, 2, 3], (2, 3): {'in_port': 1, 'out_port': 2}, (3, '10.0.0.100'): {'in_port': 2, 'out_port': 1}, 'backup_path': None}}, (1, '10.0.0.1', '10.0.0.100'): {'group_id': 0, 'instructions': {(1, 2): {'in_port': 1, 'out_port': 2}, 'primary_path': [1, 2, 3], (2, 3): {'in_port': 1, 'out_port': 2}, (3, '10.0.0.100'): {'in_port': 2, 'out_port': 1}, 'backup_path': None}}, (1, '10.0.0.100', '10.0.0.1'): {'group_id': 0, 'instructions': {'primary_path': [3, 2, 1], (3, 2): {'in_port': 1, 'out_port': 2}, (2, 1): {'in_port': 2, 'out_port': 1}, (1, '10.0.0.1'): {'in_port': 2, 'out_port': 1}, 'backup_path': None}}}

    @route('get_global_flow_table', "/get_global_flow_table/", methods=['GET'])
    def get_global_flow_table(self, req, **kwargs):
        body = json.dumps(self.get_global_flow_table)
        return Response(content_type='application/json', body=body)

    @route('create_flow', "/create_flow/", methods=['PUT'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def create_path(self, req, **kwargs):
        print req.body
        self.cool_main_program.flow_management.create_flow(sw_src=1, sw_dst=3,ipv4_src='10.0.0.1', ipv4_dst='10.0.0.100')
        print "Finished!"

class CongestionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(CongestionController, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(COOL_Interface, {simple_switch_instance_name: self})

if __name__ == '__main__':
    global_flow_table = {1: {'group_id': 0, 'match': '10.0.0.1', 'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 2, 'in_port': 1}, (1, '10.0.0.1'): {'out_port': 1, 'in_port': 2}, (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}}, 2: {'group_id': 0, 'match': '10.0.0.1', 'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 2, 'in_port': 1}, (1, '10.0.0.1'): {'out_port': 1, 'in_port': 2}, (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}}, 3: {'group_id': 0, 'match': '10.0.0.1', 'instructions': {'primary_path': [3, 2, 1], (3, 2): {'out_port': 2, 'in_port': 1}, (1, '10.0.0.1'): {'out_port': 1, 'in_port': 2}, (2, 1): {'out_port': 1, 'in_port': 2}, 'backup_path': None}}}
    json.dumps(global_flow_table)