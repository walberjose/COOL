#Manipulate IP addresses
from netaddr import *


class Domain_Controller():

    def __init__(self, topology_management=None,flow_management=None,policy_management=None):
        self.flow_management = flow_management
        self.topology_management = topology_management
        self.policy_management = policy_management
        # Cool-topology.py
        #self.networks = self.populate_paper_networks_COOL()
        #self.hosts = self.populate_paper_hosts_COOL()  # Uses paper: cool-topology.py

    '''
    Methods for Northbound Interface
    '''

    def enable_BGP_Speaker(self):
        return self.topology_management.enable_BGP_Speaker()


    def hello_world(self):
        return "Hello World!"



    '''
    Methods for topology management
    '''

    #Update the flow stats of the DPID
    def topology_management_set_flow_stats(self,dpid, body):
        self.topology_management.set_flow_stats(dpid, body)

    def topology_management_link_down(self,sw_src,sw_dst):
        self.topology_management.link_down(sw_dst, sw_src)

    #Not working:
    def topology_management_link_up(self, sw_src, sw_dst):
        #self.topology_management.link_down(sw_dst, sw_src)
        self.flow_management.link_down(self.topology_management.get_topology(), sw_src,
                                       sw_dst)

    def topology_management_switch_down(self, sw_id):
        self.topology_management.remove_node(sw_id)
        # self.flow_management.topology.remove_node(dpid)
        # print self.flow_management.topology
        del self.flow_management.datapaths[sw_id]
        # print self.flow_management.datapaths

    def topology_management_switch_enter(self, switch_list,links_list):
        #switch_list = get_switch(self, None)
        for switch in switch_list:
            # print switch.dp.id,"!!!!!!!!!!!!!!!!!!!!"
            if switch.dp.id not in self.flow_management.datapaths:
                self.flow_management.datapaths[switch.dp.id] = switch.dp

        switches = [switch.dp.id for switch in switch_list]
        #links_list = get_link(self, None)
        # print links_list
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # print links, "Links<<<<<<<<<<<<<<<<<"
        # [(2, 3, {'port': 3}), (2, 1, {'port': 2}), (3, 2, {'port': 2}), (1, 2, {'port': 2})] Links << << << << << << << << <
        for link in links:
            src, dst, port = link
            self.topology_management.add_edge(src, dst, {'port': port})

    def topology_management_add_edge(self, sw_src, sw_dst, port):
        self.topology_management.add_edge(sw_src, sw_dst, {'port':  port})


    '''
    Methods for flow management
    '''
    #Update the number of flows for the datapaths
    def flow_management_set_number_of_flows(self,dpid, flow_count):
        self.flow_management.set_number_of_flows(dpid, flow_count)

    def flow_management_link_down(self,sw_src,sw_dst):
        self.flow_management.link_down(self.topology_management.get_topology(), sw_src,
                                       sw_dst)  # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    def flow_management_flow_removed(self,dpid,ipv4):
        self.flow_management.removed_flow(dpid, ipv4)

    #dpid -> integer, datapath-> Object datapath
    def flow_management_add_datapaths(self,dpid,datapath):
        if dpid not in self.flow_management.datapaths:
            self.flow_management.datapaths[dpid] = datapath

    def flow_management_treat_arp(self,arp_pkt,in_port,eth_pkt,datapath):
        self.flow_management.treat_arp(arp_pkt, in_port, eth_pkt, datapath)

    def flow_management_is_a_controller_IP(self, ip_dst):
        return self.flow_management.is_a_controller_IP(ip_dst)

    def flow_management_treat_icmp(self,pkt, in_port, eth_pkt, datapath):
        self.flow_management.treat_icmp(pkt, in_port, eth_pkt, datapath)


    def flow_management_flow_creation(self, ip_src, ip_dst, msg):
        self.flow_management.flow_creation(self.topology_management.get_topology(), ip_src, ip_dst, msg)
    '''
    Methods for policy management
    '''
    #def policy_management_


    '''
    Anothers methods
    '''

    def get_hosts(self):
        pass
        #return str(self.hosts)
