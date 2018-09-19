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

import eventlet

# BGPSpeaker needs sockets patched
eventlet.monkey_patch()

# initialize a log handler
# this is not strictly necessary but useful if you get messages like:
#    No handlers could be found for logger "ryu.lib.hub"
import logging
import sys
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stderr))

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.app.COOL.cool_utils import flow_creator

# Lib to manipulate TCP/IP packets
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import bgp

from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker

#Manipulate IP addresses
from netaddr import *

# Generate the graph topology
import networkx as nx

#Manipulate IP addresses
from netaddr import *

from ryu.app.COOL.topology_management.neighbor_bgp import Neighbor

#Enable multithread in Ryu (Eventle)
from ryu.lib import hub
'''

Using VirtualBox to generate r1,r2 and r3.



10.0.254.1               192.168.25.101
  |             10.0.1.0/24       |       172.16.1.0/24
  \_____            _______ r1: bgp65001_________
        Controller /.254  .1            .1       \
             __|__/_                              \________
            |       |                             |        |    172.16.0.3/24
AS 65502    |  s2   |                             |   s1   |------- r3: bgp65501
            |_______|                             |________|
            /  | | \ .254  .2            .2       /
           /   | |  \_______ r2: bgp65002________/
         h4  h5  h6  10.0.2.0/24   |          172.16.2.0/24
        \_________/          192.168.25.102
            |
        192.168.2.0/24



'''

'''
sudo /usr/bin/python2.7 "/home/walber/Dropbox/SDN - Controllers/ryu/ryu/app/COOL/topology_management/bgp_speaker.py"
'''

class BGP_Speaker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, hosts=None, networks=None, *args, **kwargs):
        super(BGP_Speaker, self).__init__(*args, **kwargs)
        self.networks = networks
        self.hosts = hosts
        # Configuring AS 65501:
        self.as_number = 65001
        #self.remote_as = 65501
        self.router_id = '192.168.25.7'
        self.router_next_hop = "10.0.254.254" # The source IP of the BGP
        self.listen_port = 179
        self.bgp_speaker = \
            BGPSpeaker(self.as_number,
                       self.router_id,
                       bgp_server_port=self.listen_port,
                       best_path_change_handler=self.best_path_change_handler,
                       peer_down_handler=self.peer_down_handler,
                       peer_up_handler=self.peer_up_handler)
        # print "<<<<<<<<<",self.bgp_speaker

        # speaker = BGPSpeaker(as_number=65001, router_id='192.168.25.7',
        #                      best_path_change_handler=dump_remote_best_path_change,
        #                      peer_down_handler=detect_peer_down)
        self.neighbor1 = Neighbor(ip="192.168.25.2",asn=65002,next_hop="10.0.1.254",border_switch=2,sw_port=1,controller_ip="10.0.1.254")
        #self.neighbor2 = Neighbor(ip="10.0.2.2", asn=65002,next_hop="10.0.1.254", border_switch=2, sw_port=2, controller_ip="10.0.1.254")
        # self.neighbor = {"10.0.1.1": {'asn': 65001,'switch':2, 'port': 1,'controller_ip':"10.0.1.254"},
        #                  "10.0.2.2": {'asn': 65002,'switch':2, 'port': 2,'controller_ip':"10.0.2.254"},
        #                  }
        self.neighbors = [self.neighbor1]#,self.neighbor2]
        #self.local_networks = {"192.168.2.0/24":{'controller_ip':"192.168.2.254"}}
        self.prefix_add(prefix="192.168.2.0/24",next_hop="192.168.2.254")
        # Adding neighbors:
        #TODO: Verify the option of next_hop
        for neighbor in self.neighbors:
            # self.bgp_speaker.neighbor_add(address=neighbor, remote_as=self.neighbor[neighbor]['asn'],
            #                               next_hop=self.router_next_hop,
            #                               is_next_hop_self=True)
            self.neighbors_add(neighbor)
            # for network in self.local_networks:
            #     # Adding prefixes:
            #     self.bgp_speaker.prefix_add(network, self.neighbor[neighbor]['controller_ip'])  # next_hop (how to reach the network)
            #     #self.bgp_speaker.prefix_add("192.168.2.0/24", "10.0.2.254")  # next_hop (how to reach the network)
            #     # self.bgp_speaker.prefix_add("10.0.0.0/24", "10.0.1.1")

        # "10.0.3.1": 'fe:00:00:00:00:03'}
        # self.arp_controller = '00:00:00:00:00:fe'
        # self.monitor_thread = hub.spawn(self._monitor)
        # self.best_paths ={}

        self.prefix_learned = {}  # "198.51.100.0/24",'10.0.1.0/24'}

        self.is_load_balancer_active = False
        self.load_balancer = {}

        #self.monitor_thread = hub.spawn(self.stand_alone)
        print "BGP Speaker started! ;)"
        self.stand_alone()

    def stand_alone(self):
        #print "Oi"
        while True:
            eventlet.sleep(3)
            """ This method returns the BGP adj-RIB-in/adj-RIB-out information
                    in a json format."""
            #print "Sent routes:",self.bgp_speaker.neighbor_get(route_type='sent-routes', address=self.neighbor1.get_IP(),
            #                                    format='json')
            #print '\nReceived-routes:',self.bgp_speaker.neighbor_get(route_type='received-routes',address=self.neighbor1.get_IP(),format='json')
            self.prefix_add("10.0.0.0/24","10.0.0.1")
            #print self.get_cool_rib(),"\n\n\n"

    def prefix_add(self,prefix,next_hop):
        '''``prefix`` must be the string representation of an IP network
        (e.g., 10.1.1.0/24).

        ``next_hop`` specifies the next hop address for this
        prefix. This parameter is necessary for only VPNv4 and VPNv6
        address families.'''
        self.bgp_speaker.prefix_add(prefix,next_hop)


    def neighbors_add(self, neighbor):
        if isinstance(neighbor,Neighbor):
            self.bgp_speaker.neighbor_add(address=neighbor.get_IP(),#neighbor,
                                          remote_as=neighbor.get_ASN(),#self.neighbor[neighbor]['asn'],
                                          next_hop=neighbor.get_next_hop(),#self.router_next_hop,
                                          is_next_hop_self=True)
        else:
            print "Object is not the type Neighbor! type:",type(neighbor),type(Neighbor),neighbor

    def get_cool_rib(self):
        # from ryu.services.protocols.bgp.api.base import call
        # show = {
        #     'params': ['rib', 'ipv4'],
        #     'format': format
        # }
        #
        # call('operator.show', **show)
        from ryu.services.protocols.bgp.operator.internal_api import InternalApi
        INTERNAL_API = InternalApi()#_init_log_handler())

        # table_manager = self.get_core_service().table_manager
        # gtable = table_manager.get_global_table_by_route_family(rf)
        return INTERNAL_API.get_single_rib_routes('ipv4')

    def update_networks_from_rib(self):
        from ryu.services.protocols.bgp.operator.internal_api import InternalApi
        INTERNAL_API = InternalApi()
        rib_bgp = INTERNAL_API.get_single_rib_routes('ipv4')
        print rib_bgp
        to_delete = {}
        for route in rib_bgp:
            prefix = route['prefix']
            paths = route['paths']
            best_hop = None
            list_of_next_hops = []
            for index,path in enumerate(paths):
                aspath = path['aspath']
                if aspath == []:
                    continue
                nexthop = path['nexthop']
                list_of_next_hops.append(nexthop)
                is_best_route = path['best']
                if is_best_route:
                    best_hop = nexthop
                ip = IPNetwork(prefix)  # ("172.16.0.0/24")
                ip_network = str(ip.network)
                # mask_value = ip.prefixlen
                # netmask = ip.netmask
                #print prefix,'\n\n\n'
                if ip_network not in self.networks:
                    switch = self.neighbor[nexthop]['switch']
                    port = self.neighbor[nexthop]['port']
                    controller_ip = None
                    if aspath == []: # aspath = [] means that this prefix is local
                        controller_ip = self.local_networks[prefix]['controller_ip']
                    else:
                        controller_ip = self.hosts['neighbors'][nexthop]['controller_ip']
                    self.networks[ip_network] = {'mask':str(ip.netmask),'controller_ip':controller_ip,
                                                 'next_hop':{nexthop:{'switch':switch,'port':port,'bandwidth': 0,'congested':0}},
                                                 'as_path':aspath,
                                                 'best_hop':nexthop}
                else:
                    best_next_hop = self.networks[ip_network]['best_hop']
                    if best_hop != best_next_hop:
                        self.networks[ip_network]['next_hop']['best_hop'] = best_hop
                    if nexthop not in self.networks[ip_network]['next_hop']:
                        switch = self.neighbor[nexthop]['switch']
                        port = self.neighbor[nexthop]['port']
                        controller_ip = None
                        if aspath == []:  # aspath = [] means that this prefix is local
                            controller_ip = self.local_networks[prefix]['controller_ip']
                        else:
                            controller_ip = self.hosts['neighbors'][nexthop]['controller_ip']
                        self.networks[ip_network]['next_hop'][nexthop] = {'switch':switch,'port':port,'bandwidth': 0,'congested':0}
                    else:
                        #I  dont know if it is necessary to change
                        pass
                    self.networks[ip_network]['as_path'] = aspath

            ip = IPNetwork(prefix)  # ("172.16.0.0/24")
            ip_network = str(ip.network)
            if ip_network in self.networks:
                for nexthop in self.networks[ip_network]['next_hop']:
                    if nexthop not in list_of_next_hops:
                        del self.networks[ip_network]['next_hop'][nexthop]


                        # How it should be:
        # networks = {'10.0.2.0': {'controller_ip':"10.0.2.254",'mask': '255.255.255.0',
        #                         'next_hop': {"10.0.2.2": {'switch': 2, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"10.0.2.2"},
        #         '10.0.1.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
        #                         'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"10.0.1.1"},
        #         '172.16.0.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
        #                         'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1,'bandwidth': 0,'congested':0},
        #                                      "10.0.2.2": {'switch': 2, 'port': 2,'bandwidth': 0,'congested':0}},
        #                                      'best_hop': "10.0.1.1"},
        #         '10.0.254.0': {'controller_ip':"10.0.254.254",'mask': '255.255.255.0',
        #                         'next_hop': {"10.0.254.1": {'switch': 2, 'port': 6,'bandwidth': 0,'congested':0}},'best_hop':"10.0.254.1"}
        #         }


    def peer_down_handler(self, remote_ip, remote_as):
        print "peer_down_handler"
        self.logger.info('peer down:')
        self.logger.info('remote_as: %d', remote_as)
        self.logger.info('remote ip: %s', remote_ip)
        self.logger.info('')
        for network in self.networks.keys():
            for next_hop in self.networks[network]['next_hop'].keys():
                if str(remote_ip) == next_hop:
                    del self.networks[network]['next_hop'][next_hop]



    def peer_up_handler(self, remote_ip, remote_as):
        print "peer_up_handler"
        self.logger.info('peer up:')
        self.logger.info('remote_as: %d', remote_as)
        self.logger.info('remote ip: %s', remote_ip)
        self.logger.info('')

    def best_path_change_handler(self, ev):
        print "Best paht changed! ",ev
        #self.update_networks_from_rib()
        #self.prefix_learned["OI"] = "Path changed!"
        self.logger.info('best path changed:')
        self.logger.info('remote_as: %d', ev.remote_as)
        self.logger.info('route_dist: %s', ev.route_dist)
        self.logger.info('prefix: %s', ev.prefix)
        self.logger.info('nexthop: %s', ev.nexthop)
        self.logger.info('label: %s', ev.label)
        self.logger.info('path: %s', ev.path)
        self.logger.info('peer: %s %s' % (ev.path._source, type(ev.path._source)))
        self.logger.info('peer ip: %s' % ev.path._source.ip_address)
        if True:
            return
        self.logger.info('Port: %s' % self.neighbor[ev.path._source.ip_address]['port'])
        self.logger.info('is_withdraw: %s', ev.is_withdraw)
        self.logger.info('')

        """
        ev.path:
        data: {'path': Path(Peer(ip: 192.168.25.51, asn: 65501)
        peer: Peer(ip: 192.168.25.51, asn: 65501)
        NLRI: network layer reachability information. For IPv4 is all about send prefix information. 
        With other addresses families it can carry other types of information
        Received msg from ('10.0.1.51', '46426') << BGPUpdate(len=52,nlri=[BGPNLRI(addr='198.51.100.0',length=24)],path_attributes=[BGPPathAttributeOrigin(flags=64,length=1,type=1,value=0), BGPPathAttributeAsPath(flags=80,length=10,type=2,value=[[65501, 65500]]), BGPPathAttributeNextHop(flags=64,length=4,type=3,value='10.0.1.51')],total_path_attribute_len=25,type=2,withdrawn_routes=[],withdrawn_routes_len=0)
NLRI: BGPNLRI(addr='198.51.100.0',length=24)
Extracted paths from Update msg.: 
Path(source: Peer(ip: 10.0.1.51, asn: 65501), nlri: BGPNLRI(addr='198.51.100.0',length=24), source ver#: 1, 
path attrs.: {1: BGPPathAttributeOrigin(flags=64,length=1,type=1,value=0), 
2: BGPPathAttributeAsPath(flags=80,length=10,type=2,value=[[65501, 65500]]), 
3: BGPPathAttributeNextHop(flags=64,length=4,type=3,value='10.0.1.51')}, nexthop: 10.0.1.51, is_withdraw: False)

        return ('Path(%s, %s, %s, %s, %s, %s)' % (
            self._source, self._nlri, self._source_version_num,
            self._path_attr_map, self._nexthop, self._is_withdraw))

            Used to pass an update on any best remote path to
            best_path_change_handler.

            ================ ======================================================
            Attribute        Description
            ================ ======================================================
            remote_as        The AS number of a peer that caused this change
            route_dist       None in the case of IPv4 or IPv6 family
            prefix           A prefix was changed
            nexthop          The nexthop of the changed prefix
            label            MPLS label for VPNv4, VPNv6 or EVPN prefix
            path             An instance of ``info_base.base.Path`` subclass
            is_withdraw      True if this prefix has gone otherwise False
            ================ ======================================================
            """

        print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nCreate a rule for %s with next hop %s and port %s" % (
        ev.prefix, ev.nexthop, self.neighbor[ev.path._source.ip_address]['port'])


        print "AS path:", ev.path
        print "AS path attributes:", ev.path._path_attr_map
        print "AS path attributes, AS_Path:", ev.path.get_pattr(bgp.BGP_ATTR_TYPE_AS_PATH)
        print "AS path attributes, AS_Path value:", ev.path.get_pattr(bgp.BGP_ATTR_TYPE_AS_PATH).value
        # Check if the prefix already has been learned
        if ev.prefix not in self.prefix_learned:
            ip = IPNetwork(ev.prefix)#("172.16.0.0/24")
            #print ip.network, ip.prefixlen???
            switch = self.neighbor[ev.path._source.ip_address]['switch']
            port = self.neighbor[ev.path._source.ip_address]['port']
            as_path = ev.path.get_pattr(bgp.BGP_ATTR_TYPE_AS_PATH).value
            self.prefix_learned[ev.prefix] = {'next_hop': {ev.nexthop:{ 'switch':switch,
                                                                        'port':port,'as_path':as_path,
                                                                        'neighbor': ev.path._source.ip_address}
                                                            }
                                              }
        else:
            switch = self.neighbor[ev.path._source.ip_address]['switch']
            port = self.neighbor[ev.path._source.ip_address]['port']
            as_path = ev.path.get_pattr(bgp.BGP_ATTR_TYPE_AS_PATH).value
            if ev.nexthop not in self.prefix_learned[ev.prefix]['next_hop']:
                self.prefix_learned[ev.prefix]['next_hop'] = {ev.nexthop: {'switch': switch,
                                                                           'port': port, 'as_path': as_path,
                                                                           'neighbor': ev.path._source.ip_address}
                                                              }
            else:
                self.prefix_learned[ev.prefix]['next_hop'][ev.nexthop] =  {'switch': switch,
                                                                           'port': port, 'as_path': as_path,
                                                                           'neighbor': ev.path._source.ip_address}


            #{'172.16.0.0/24': {'paths': [[65001, 65501]], 'next_hop': '10.0.1.1', 'port': 1, 'neighbor': '10.0.1.1'}}"
            #How it should be:
            # networks = {'10.0.2.0': {'controller_ip':"10.0.2.254",'mask': '255.255.255.0',
            #                         'next_hop': {"10.0.2.2": {'switch': 2, 'port': 2,'bandwidth': 0,'congested':0}},'best_hop':"10.0.2.2"},
            #         '10.0.1.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
            #                         'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1,'bandwidth': 0,'congested':0}},'best_hop':"10.0.1.1"},
            #         '172.16.0.0': {'controller_ip':"10.0.1.254",'mask': '255.255.255.0',
            #                         'next_hop': {"10.0.1.1": {'switch': 2, 'port': 1,'bandwidth': 0,'congested':0},
            #                                      "10.0.2.2": {'switch': 2, 'port': 2,'bandwidth': 0,'congested':0}},
            #                                      'best_hop': "10.0.1.1"},
            #         '10.0.254.0': {'controller_ip':"10.0.254.254",'mask': '255.255.255.0',
            #                         'next_hop': {"10.0.254.1": {'switch': 2, 'port': 6,'bandwidth': 0,'congested':0}},'best_hop':"10.0.254.1"}
            #         }
            # self.prefix_learned[ev.prefix]['next_hop'] = ev.nexthop
            # self.prefix_learned[ev.prefix]['neighbor'] = ev.path._source.ip_address
            # self.prefix_learned[ev.prefix]["port"] = self.neighbor[ev.path._source.ip_address]['port'],
            # self.prefix_learned[ev.prefix]['paths'] += ev.path.get_pattr(bgp.BGP_ATTR_TYPE_AS_PATH).value

        #   The result self.prefix_learned:
        # {'172.16.0.0/24': {'paths': [[65001]], 'next_hop': '192.168.25.101', 'port': 1, 'neighbor': '192.168.25.101'}}
        if ev.is_withdraw:  # Remove prefix that is withdraw
            ip = IPNetwork(ev.prefix)  # ("172.16.0.0/24")
            ip_network = str(ip.network)
            next_hop = ev.nexthop
            # if ip_network in self.networks:
            #     del self.networks[ip_network]['next_hop'][next_hop]

            #del self.prefix_learned[ev.prefix]
            # TODO:
            # self.prefix_learned[ev.prefix] = {  'paths': {  'next_hop': ev.nexthop,
            #                                                 'path':     ev.path.path_attrs,
            #                                                 "port":     self.neighbor[ev.path._source.ip_address]['port']}
            #                                  }

            # print "BEST PATH! :)"


if __name__ == '__main__':
    # ip = IPNetwork("172.16.0.0/24")
    # print ip.network,ip.prefixlen,ip.netmask
    # pass
    # topo = Topology_discover(None, None, None)
    # links = [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})]
    # topology = topo.topology
    # topology.add_nodes_from(switches)
    bgp_speaker = BGP_Speaker(None)
    if True==True:
        pass
    else:
        list_of_paths = [{'paths': [{'origin': 'num_flows', 'aspath': [], 'prefix': '10.0.0.0/24', 'bpr': 'Only Path', 'localpref': '', 'nexthop': '10.0.0.1', 'metric': '', 'labels': None, 'best': True}], 'prefix': '10.0.0.0/24'}, {'paths': [{'origin': 'num_flows', 'aspath': [], 'prefix': '192.168.2.0/24', 'bpr': 'Only Path', 'localpref': '', 'nexthop': '192.168.2.254', 'metric': '', 'labels': None, 'best': True}], 'prefix': '192.168.2.0/24'}]
        for path in list_of_paths:
            print path,"\n"#,list[i]
            for key in path:
                print key,"<key"
                print path[key]