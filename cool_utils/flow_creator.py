import logging
__author__ = 'walber'

from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.ofproto import ether
from ryu.ofproto import inet

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp


#dpctl dump-groups -O OpenFlow13
#dpctl dump-flows -O OpenFlow13

def treat_arp( arp_pkt, in_port, eth_pkt, datapath, hosts):
    # treat arp broadcast requests:
    if arp_pkt.dst_mac == '00:00:00:00:00:00':
        # treat arp broadcast for the controller:
        #print arp_pkt, in_port, eth_pkt, datapath, hosts,"KKKKKKKKKKKKK"
        if arp_pkt.dst_ip in hosts['controller']:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                #self.logger.debug("ARP type request to the controller %s.", arp_pkt.dst_ip)
                _handle_arp(datapath, in_port, eth_pkt, arp_pkt, hosts['controller'][arp_pkt.dst_ip]['arp'],
                                         arp_pkt.dst_ip)
                #self.logger.debug("Sended ARP the controller")
                return 0
            elif arp_pkt.opcode == arp.ARP_REPLY:
                # Exclude this code:
                pass
                # print "Server %s MAC %s is alive at %s port! "%(arp_pkt.src_ip,arp_pkt.src_mac,in_port)
                # self.live_servers[arp_pkt.src_ip]=arp_pkt.src_mac,in_port

        elif arp_pkt.dst_ip in hosts:
            # print "\n\n\n>>>>>>>>>>>Arp to ", arp_pkt.dst_ip
            _handle_arp(datapath, in_port, eth_pkt, arp_pkt, hosts[arp_pkt.dst_ip]['arp'],
                                     arp_pkt.dst_ip)
            # packets_handler.create_l2_flow(datapath,in_port,out_port=self.hosts[arp_pkt.dst_ip]['port'])
        # treat arp for someone else:
        else:
            print "Dont know!", arp_pkt.dst_ip


def treat_icmp(pkt, in_port, eth_pkt, datapath, hosts):
    # treat ICMP packets for the controller
    icmp_pkt = pkt.get_protocol(icmp.icmp)
    ip_pkt = pkt.get_protocol(ipv4.ipv4)
    if icmp_pkt:
        _handle_icmp(datapath, in_port, eth_pkt, ip_pkt, icmp_pkt, hosts['controller'][ip_pkt.dst]['arp'], ip_pkt.dst)


def _handle_arp(datapath, in_port, pkt_ethernet, pkt_arp, hw_addr, ip_addr):
    if pkt_arp.opcode != arp.ARP_REQUEST:
        return
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                       dst=pkt_ethernet.src,
                                       src=hw_addr))
    pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                             src_mac=hw_addr,
                             src_ip=ip_addr,
                             dst_mac=pkt_arp.src_mac,
                             dst_ip=pkt_arp.src_ip))
    _send_packet(datapath, in_port, pkt)

def _send_arp_request(datapath, out_port, eth_src, eth_dst, ipv4_src,ipv4_dst):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                       dst=eth_dst,
                                       src=eth_src))
    pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                             src_mac=eth_src,
                             src_ip=ipv4_src,
                             dst_mac=eth_dst,
                             dst_ip=ipv4_dst))
    _send_packet(datapath, out_port, pkt)


def _handle_icmp(datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp, hw_addr, ip_addr):
# code you want to evaluate

    if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
        return
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                       dst=pkt_ethernet.src,
                                       src=hw_addr))
    pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                               src=ip_addr,
                               proto=pkt_ipv4.proto))
    pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                               code=icmp.ICMP_ECHO_REPLY_CODE,
                               csum=0,
                               data=pkt_icmp.data))
    _send_packet(datapath, in_port, pkt)
    #datapath.send_msg(pkt)


def _send_packet(datapath, out_port, pkt):
    # print "Enviar o pacote para porta: %s no switch: %s"%(out_port,datapath.id)
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    pkt.serialize()
    #logger.info("packet-out %s" % (pkt,))
    data = pkt.data


    #print "\n\n\nAQUIIIIII"
    #print data

    actions = [parser.OFPActionOutput(port=out_port)]
    #print actions
    out = parser.OFPPacketOut(datapath=datapath,
                              buffer_id=ofproto.OFP_NO_BUFFER, # If OFPCML_NO_BUFFER is specified, the entire packet is attached to
                                                               # the Packet-In message without buffering the packet on the OpenFlow switch.
                              in_port=ofproto.OFPP_CONTROLLER, # Sent to the controller as a Packet-In message.
                              actions=actions,
                              data=data)
    #print out
    datapath.send_msg(out)


def create_l2_vlan_flow(datapath,sw_header,sw_tail,vlan_tag, in_port, out_port, ip_pkt_src, ip_pkt_dst,msg,priority= 32768, modify_rule = False):

    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser
    match = None
    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 15
    hard_timeout = 3600
    #priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

    actions = None
    #match = None

    if datapath.id == sw_header:
        # ICMP -> PushVLAN(9)
    #     LOG.debug("--- add_flow ICMP to PushVLAN(9)")
    #     s_vid = 9
    #     eth_IP = ether.ETH_TYPE_IP
    #     eth_VLAN = ether.ETH_TYPE_8021Q
    #     ip_ICMP = inet.IPPROTO_ICMP
    #     match = ofp_parser.OFPMatch()
    #     match.set_in_port(in_port)
    #     match.set_dl_type(eth_IP)
    #     match.set_ip_proto(ip_ICMP)
    #     f = ofp_parser.OFPMatchField.make(
    #         datapath.ofproto.OXM_OF_VLAN_VID, vlan_tag)
    #     actions = [datapath.ofproto_parser.OFPActionPushVlan(eth_VLAN),
    #                datapath.ofproto_parser.OFPActionSetField(f),
    #                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
    # self._add_flow(dp, match, actions)
        print "Push a VLAN tag:\n\n\n\n"
        #Push a VLAN tag:
        #Only packets without a VLAN tag:
        #match = ofp_parser.OFPMatch()
        match = OFPMatch(eth_type=ether_types.ETH_TYPE_IP,#ipv4_src=ip_pkt_src,
                           ipv4_dst=ip_pkt_dst)
        #match.set_ip_proto(ipv4.inet.IPPROTO_IP)
        tag = ofp_parser.OFPMatchField.make(
            ofp.OXM_OF_VLAN_VID, vlan_tag)
        actions = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                   ofp_parser.OFPActionSetField(vlan_vid=(0x1000 |vlan_tag))]

    elif datapath.id == sw_tail:
        print "Pop a VLAN tag:\n\n\n\n"
        # Pop a VLAN tag:
        match = OFPMatch(vlan_vid=(0x1000 |vlan_tag), eth_type=ether_types.ETH_TYPE_IP,#ipv4_src=ip_pkt_src,
                          ipv4_dst=ip_pkt_dst)
        actions = [ofp_parser.OFPActionPopVlan()]

    else:
        print "Forward the VLAN tag:\n\n\n\n"
        match = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag))
        actions = []


    #Default action:
    actions.append(ofp_parser.OFPActionOutput(port=out_port))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]

    add_or_mod_a_rule = ofp.OFPFC_ADD
    if modify_rule:
        add_or_mod_a_rule = ofp.OFPFC_MODIFY

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, add_or_mod_a_rule,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print datapath.id,":",req
    datapath.send_msg(req)

def create_simple_l3_flow(datapath, in_port, out_port, ip_pkt_src, ip_pkt_dst, msg, priority= 32768, modify_rule = False):
    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 15
    hard_timeout = 3600
    #priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
    match = OFPMatch(#in_port=in_port,
                     eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ip_pkt_src, ipv4_dst=ip_pkt_dst)#(ip_pkt_dst, "255.255.255.0"))

    actions = []


    actions.append(ofp_parser.OFPActionOutput(port=out_port))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]

    add_or_mod_a_rule = ofp.OFPFC_ADD
    if modify_rule:
        add_or_mod_a_rule = ofp.OFPFC_MODIFY

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, add_or_mod_a_rule,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print datapath.id,":",req
    datapath.send_msg(req)


def create_l3_flow_with_wildcard(datapath, in_port, out_port, ip_pkt_src, ip_pkt_dst,msg,priority= 32768, modify_rule = False):
    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 15
    hard_timeout = 3600
    #priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        print msg
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
    match = OFPMatch(#in_port=in_port,
                     eth_type=ether_types.ETH_TYPE_IP,#ipv4_src=ip_pkt_src,
                         ipv4_dst=ip_pkt_dst)#(ip_pkt_dst, "255.255.255.0"))

    actions = []


    actions.append(ofp_parser.OFPActionOutput(port=out_port))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]

    add_or_mod_a_rule = ofp.OFPFC_ADD
    if modify_rule:
        add_or_mod_a_rule = ofp.OFPFC_MODIFY

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, add_or_mod_a_rule,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print datapath.id,":",req
    datapath.send_msg(req)

# flow_creator.create_routing_with_wildcard(datapaths[node], in_port, out_port=out_port,
#                                                           set_arp_dst,set_arp_src,network,network_mask,
#                                                           msg=msg,priority= 50000,
#                                                           modify_rule=modify_rule)
def create_routing_with_wildcard(datapath, in_port, out_port,set_arp_dst,set_arp_src,network,network_mask,msg,priority= 32768, modify_rule = False,routing_instructions=None):
    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 15
    hard_timeout = 3600
    #priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
    match = OFPMatch(in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=(network, network_mask))
    # match = ofp_parser.OFPMatch(in_port=4,eth_type=ether_types.ETH_TYPE_IP, eth_dst=lb_eth)

    # match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_src=ip_pkt.src,
    #                             ipv4_dst=lb_ipv4, tcp_src=tcp_pkt.src_port,
    #                             tcp_dst=tcp_pkt.dst_port)

    actions = [ofp_parser.OFPActionSetField(eth_dst=set_arp_dst)]
    actions.append(ofp_parser.OFPActionSetField(eth_src=set_arp_src))
    actions.append(ofp_parser.OFPActionOutput(port=out_port))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]

    add_or_mod_a_rule = ofp.OFPFC_ADD
    if modify_rule:
        add_or_mod_a_rule = ofp.OFPFC_MODIFY

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, add_or_mod_a_rule,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print datapath.id,":",req
    datapath.send_msg(req)



def create_l3_flow(datapath, in_port, out_port, eth_pkt, ip_pkt,msg):
    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 60
    #hard_timeout = 31
    hard_timeout = 3600
    priority = 32768
    buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
    data = None
    if msg.buffer_id == ofp.OFP_NO_BUFFER:
        data = msg.data
    match = OFPMatch(in_port=in_port,eth_type=ether_types.ETH_TYPE_IP,
                        eth_dst = eth_pkt.dst,#eth_src = eth_pkt.src,
                        ipv4_src=ip_pkt.src,ipv4_dst=(ip_pkt.dst,"255.255.255.0"))


    actions = [ofp_parser.OFPActionOutput(port=out_port)]
    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, ofp.OFPFC_ADD,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    #print datapath.id,":",req
    datapath.send_msg(req)

def create_group_mod_failover_flow(datapath, group_id, out_port, backup_output_port=0,create_group_id=False):
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    port = out_port
    actions = [ofp_parser.OFPActionOutput(out_port)]

    weight = 0
    #watch_port = 1 #As such, the watch port is the same as the port we will use as an output action in the bucket's actions.
    watch_port = out_port
    watch_group = ofp.OFPG_ANY

    buckets =[]
    if create_group_id:
        if backup_output_port == 0:
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,actions)]
            #print "Aqui naooooooo!"
        else:
            #print "Aqui simmmmmmmmm!",out_port,backup_output_port
            failover_watch_port = backup_output_port
            failover_watch_group = ofp.OFPG_ANY
            failover_actions = [ofp_parser.OFPActionOutput(backup_output_port)]
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group, actions),
                       ofp_parser.OFPBucket(weight, failover_watch_port, failover_watch_group, failover_actions)]
        # group_id = 1
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_FF, group_id, buckets)
        print "Creating FF group table for ",datapath.id,req
        datapath.send_msg(req)
    else:
        if backup_output_port == 0:
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,actions)]
            #print "Aqui naooooooo!"
        else:
            failover_watch_port = backup_output_port
            failover_watch_group = ofp.OFPG_ANY
            failover_actions = [ofp_parser.OFPActionOutput(backup_output_port)]
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group, actions),
                       ofp_parser.OFPBucket(weight, failover_watch_port, failover_watch_group, failover_actions)]

        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_MODIFY,
                                     ofp.OFPGT_FF, group_id, buckets)
        print "Modifing FF group table:",req
        datapath.send_msg(req)
        return 0

def create_group_mod_failover_flow_with_vlan(datapaths,sw_src,instructions, group_id,create_group_id=False):
    has_backup_path = instructions[sw_src]['has_failover_path']
    failover_in_port = instructions[sw_src]['failover_in_port']
    backup_switch = instructions[sw_src]['backup_switch']
    failover_out_port = instructions[sw_src]['failover_out_port']

    primary_output_port = instructions[sw_src]['out_port']
    primary_input_port = instructions[sw_src]['in_port']
    sw_dst = instructions[sw_src]['forward_switch']
    vlan_tag = instructions[sw_src]['vlan']
    vlan_tag_failover = instructions[sw_src]['vlan_tag_failover']

    datapath = datapaths[sw_src]
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    primary_path_actions = None
    backup_path_actions = None

    primary_path = instructions['primary_path']
    backup_path = instructions['backup_path']

    sw_primary_header = primary_path[0]
    sw_primary_tail = primary_path[-1]

    sw_backup_header = backup_path[0]
    sw_backup_tail = backup_path[-1]

    #Creating match and action for primary path
    if datapath.id == sw_primary_header:
        print "Push a VLAN tag:\n\n\n\n"
        primary_path_actions = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                   ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag))]

    elif datapath.id == sw_primary_tail:
        print "Pop a VLAN tag:\n\n\n\n"
        # Pop a VLAN tag:
        primary_match = OFPMatch(vlan_vid=(0x1000 | vlan_tag))#, eth_type=ether_types.ETH_TYPE_IP,  # ipv4_src=ip_pkt_src,
                         #ipv4_dst=ip_pkt_dst)
        primary_path_actions = [ofp_parser.OFPActionPopVlan()]

    else:
        print "Forward the VLAN tag:\n\n\n\n"
        match = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag))
        primary_path_actions = []

    # Default action:
    primary_path_actions.append(ofp_parser.OFPActionOutput(port=primary_output_port))

    if has_backup_path:
        if datapath.id == sw_backup_header:
            print "Push a VLAN tag:\n\n\n\n"
            backup_path_actions = [#ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                       ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag_failover))]

        elif datapath.id == sw_backup_tail:
            print "Pop a VLAN tag:\n\n\n\n"
            # Pop a VLAN tag:
            backup_match = OFPMatch(vlan_vid=(0x1000 | vlan_tag_failover))#, eth_type=ether_types.ETH_TYPE_IP,  # ipv4_src=ip_pkt_src,
                             #ipv4_dst=ip_pkt_dst)
            backup_path_actions = [ofp_parser.OFPActionPopVlan()]

        else:
            print "Forward the VLAN tag:\n\n\n\n"
            backup_match = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag_failover))
            backup_path_actions = [  # ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag_failover))]
            #backup_path_actions = []


        # Default action:
        backup_path_actions.append(ofp_parser.OFPActionOutput(port=failover_out_port))

#    actions = [ofp_parser.OFPActionOutput(out_port)]

    weight = 0
    #watch_port = 1 #As such, the watch port is the same as the port we will use as an output action in the bucket's actions.
    watch_port = primary_output_port
    watch_group = ofp.OFPG_ANY
#???
    buckets =[]
    if create_group_id:
        if not has_backup_path:
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,primary_path_actions)]
            #print "Aqui naooooooo!"
        else:
            #print "Aqui simmmmmmmmm!",out_port,backup_output_port
            failover_watch_port = failover_out_port
            failover_watch_group = ofp.OFPG_ANY
            #failover_actions = [ofp_parser.OFPActionOutput(backup_output_port)]
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group, primary_path_actions),
                       ofp_parser.OFPBucket(weight, failover_watch_port, failover_watch_group, backup_path_actions)]
        # group_id = 1
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_FF, group_id, buckets)
        print "Creating FF group table for ",datapath.id,req
        datapath.send_msg(req)
    else:
        if not has_backup_path:
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,primary_path_actions)]
            #print "Aqui naooooooo!"
        else:
            failover_watch_port = failover_out_port
            failover_watch_group = ofp.OFPG_ANY
            #failover_actions = [ofp_parser.OFPActionOutput(backup_output_port)]
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group, primary_path_actions),
                       ofp_parser.OFPBucket(weight, failover_watch_port, failover_watch_group, backup_path_actions)]

        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_MODIFY,
                                     ofp.OFPGT_FF, group_id, buckets)
        print "Modifing FF group table:",req
        datapath.send_msg(req)
        return 0

def create_failover_vlan_flow(datapath,sw_header,sw_tail,vlan_tag, in_port, out_port, ip_pkt_src, ip_pkt_dst,msg,priority= 32768, modify_rule = False):

    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser
    match = None
    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 15
    hard_timeout = 3600
    #priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

    actions = []
    #match = None

    if datapath.id == sw_header:
        # ICMP -> PushVLAN(9)
    #     LOG.debug("--- add_flow ICMP to PushVLAN(9)")
    #     s_vid = 9
    #     eth_IP = ether.ETH_TYPE_IP
    #     eth_VLAN = ether.ETH_TYPE_8021Q
    #     ip_ICMP = inet.IPPROTO_ICMP
    #     match = ofp_parser.OFPMatch()
    #     match.set_in_port(in_port)
    #     match.set_dl_type(eth_IP)
    #     match.set_ip_proto(ip_ICMP)
    #     f = ofp_parser.OFPMatchField.make(
    #         datapath.ofproto.OXM_OF_VLAN_VID, vlan_tag)
    #     actions = [datapath.ofproto_parser.OFPActionPushVlan(eth_VLAN),
    #                datapath.ofproto_parser.OFPActionSetField(f),
    #                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
    # self._add_flow(dp, match, actions)
        print "Push a VLAN tag:\n\n\n\n"
        #Push a VLAN tag:
        #Only packets without a VLAN tag:
        #match = ofp_parser.OFPMatch()
        # match = OFPMatch(eth_type=ether_types.ETH_TYPE_IP,#ipv4_src=ip_pkt_src,
        #                    ipv4_dst=ip_pkt_dst)
        match = OFPMatch(vlan_vid=(0x1000 | vlan_tag), in_port=in_port)
        #match.set_ip_proto(ipv4.inet.IPPROTO_IP)
        tag = ofp_parser.OFPMatchField.make(
            ofp.OXM_OF_VLAN_VID, vlan_tag)
        # actions = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
        #            ofp_parser.OFPActionSetField(vlan_vid=(0x1000 |vlan_tag))]

    elif datapath.id == sw_tail:
        print "Pop a VLAN tag:\n\n\n\n"
        # Pop a VLAN tag:
        match = OFPMatch(vlan_vid=(0x1000 |vlan_tag), in_port=in_port)
        # actions = [ofp_parser.OFPActionPopVlan()]

    else:
        print "Forward the VLAN tag:\n\n\n\n"
        #match = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_tag))
        match = OFPMatch(vlan_vid=(0x1000 | vlan_tag), in_port=in_port)
        actions = []


    #Default action:
    actions.append(ofp_parser.OFPActionOutput(port=out_port))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]

    add_or_mod_a_rule = ofp.OFPFC_ADD
    if modify_rule:
        add_or_mod_a_rule = ofp.OFPFC_MODIFY

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, add_or_mod_a_rule,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print datapath.id,":",req
    datapath.send_msg(req)

def create_a_group_action_instruction(datapath,primary_path_actions,failover_actions,out_port,failover_out_port,group_id,modify_rule=False):
    ofp = datapath.ofproto
    #    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser
    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 300
    # hard_timeout = 15
    hard_timeout = 3600
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER

    weight = 0
    watch_port = out_port
    watch_group = ofp.OFPG_ANY
    buckets = None
    if failover_actions == None:
        buckets = [ofp_parser.OFPBucket(weight, out_port, watch_group, primary_path_actions)]
    else:
        buckets = [ofp_parser.OFPBucket(weight, out_port, watch_group, primary_path_actions),
                   ofp_parser.OFPBucket(weight, failover_out_port, watch_group, failover_actions)]
    req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                 ofp.OFPGT_FF, group_id, buckets)
    print "Creating FF group table for ", datapath.id, req
    datapath.send_msg(req)

    pass

def create_a_group_match_instruction(datapath,msg,match,out_port,group_id,modify_rule=False):
    ofp = datapath.ofproto
    #    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser
    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 300
    # hard_timeout = 15
    hard_timeout = 3600
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

    #inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    #inst = [ofp_parser.OFPActionGroup(group_id)]
    actions = [ofp_parser.OFPActionGroup(group_id)]

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]

    #actions = [ofp_parser.OFPActionGroup(group_id)]
    add_or_mod_a_rule = ofp.OFPFC_ADD
    if modify_rule:
        add_or_mod_a_rule = ofp.OFPFC_MODIFY

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, add_or_mod_a_rule,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                # in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    datapath.send_msg(req)


def create_group_mod_select_flow(datapath, group_id, out_port, backup_output_port=0,create_group_id=False):
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    port = out_port
    actions = [ofp_parser.OFPActionOutput(out_port)]

    weight = 1
    #watch_port = 1 #As such, the watch port is the same as the port we will use as an output action in the bucket's actions.
    watch_port = out_port
    watch_group = ofp.OFPG_ANY

    buckets =[]
    if create_group_id:
        if backup_output_port == 0:
            buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,actions)]
            print "Aqui naooooooo!"
        else:
            print "Aqui simmmmmmmmm!",out_port,backup_output_port
            failover_watch_port = backup_output_port
            failover_watch_group = ofp.OFPG_ANY
            failover_actions = [ofp_parser.OFPActionOutput(backup_output_port)]
            buckets = [ofp_parser.OFPBucket(weight+1, watch_port, watch_group, actions),
                       ofp_parser.OFPBucket(weight+2, failover_watch_port, failover_watch_group, failover_actions)]
        # group_id = 1
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,ofp.OFPGT_SELECT, group_id, buckets)
        print "Creating SELECT group table for ",datapath.id,req
        datapath.send_msg(req)
    else:
        failover_watch_port = backup_output_port
        failover_watch_group = ofp.OFPG_ANY
        failover_actions = [ofp_parser.OFPActionOutput(backup_output_port)]
        buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group, actions),
                   ofp_parser.OFPBucket(weight, failover_watch_port, failover_watch_group, failover_actions)]

        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_MODIFY,
                                     ofp.OFPGT_SELECT, group_id, buckets)
        print "Modifing FF group table:",req
        datapath.send_msg(req)
        return 0

def create_l3_failover_flow(datapath, in_port, out_port, ip_pkt,msg = None, group_id=1,eth_pkt=None):
    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 600
    #hard_timeout = 31
    hard_timeout = 3600
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        print "AQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n\n\n\n\n"
        # Send the packet-In to the host:
        _send_packet(datapath, out_port, packet.Packet(msg.data))

        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
    match = None
    if eth_pkt == None:
        match = OFPMatch(#in_port=in_port,
                            eth_type=ether_types.ETH_TYPE_IP,
                            #ipv4_src=ip_pkt.src,
                            ipv4_dst=ip_pkt.dst)
    else:
        match = OFPMatch(#in_port=in_port,
                         eth_type=ether_types.ETH_TYPE_IP,
                        #eth_dst = eth_pkt.dst,eth_src = eth_pkt.src,
                        #ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst)

    #actions = [ofp_parser.OFPActionOutput(port=out_port)]
    #group_id = 1
    actions = [ofp_parser.OFPActionGroup(group_id)]



    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]


    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, ofp.OFPFC_ADD,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print "Creating flow:",datapath.id,":",in_port,out_port,req
    datapath.send_msg(req)
    #create_group_mod_failover_flow(datapath,in_port,out_port,eth_pkt,ip_pkt,group_id)
#    create_group_mod_failover_flow(datapath, in_port, out_port, eth_pkt, ip_pkt, group_id)


def create_l3_failover_flow_with_VLAN(datapaths, sw_src, instructions, group_id,msg = None):
     #create_group_id = False):
    has_backup_path = instructions[sw_src]['has_failover_path']
    failover_in_port = instructions[sw_src]['failover_in_port']
    backup_switch = instructions[sw_src]['backup_switch']
    failover_out_port = instructions[sw_src]['failover_out_port']

    primary_output_port = instructions[sw_src]['out_port']
    primary_input_port = instructions[sw_src]['in_port']
    sw_dst = instructions[sw_src]['forward_switch']
    vlan_tag = instructions[sw_src]['vlan']
    vlan_tag_failover = instructions[sw_src]['vlan_tag_failover']

    datapath = datapaths[sw_src]
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    primary_path_actions = None
    backup_path_actions = None

    primary_path = instructions['primary_path']
    backup_path = instructions['backup_path']

    sw_primary_header = primary_path[0]
    sw_primary_tail = primary_path[-1]

    sw_backup_header = backup_path[0]
    sw_backup_tail = backup_path[-1]

    # Recovering the IPv4 packet from Packet-In event
    pkt = packet.Packet(msg.data)
    ip_pkt = pkt.get_protocol(ipv4.ipv4)


    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 31
    hard_timeout = 3600
    priority = 32768
    #buffer_id = ofp.OFP_NO_BUFFER

    buffer_id = ofp.OFP_NO_BUFFER
    data = None
    if msg != None:
        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

    actions = None
    # match = None

    if datapath.id == sw_primary_header:
        # ICMP -> PushVLAN(9)
        #     LOG.debug("--- add_flow ICMP to PushVLAN(9)")
        #     s_vid = 9
        #     eth_IP = ether.ETH_TYPE_IP
        #     eth_VLAN = ether.ETH_TYPE_8021Q
        #     ip_ICMP = inet.IPPROTO_ICMP
        #     match = ofp_parser.OFPMatch()
        #     match.set_in_port(in_port)
        #     match.set_dl_type(eth_IP)
        #     match.set_ip_proto(ip_ICMP)
        #     f = ofp_parser.OFPMatchField.make(
        #         datapath.ofproto.OXM_OF_VLAN_VID, vlan_tag)
        #     actions = [datapath.ofproto_parser.OFPActionPushVlan(eth_VLAN),
        #                datapath.ofproto_parser.OFPActionSetField(f),
        #                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        # self._add_flow(dp, match, actions)
        print "Push a VLAN tag:\n\n\n\n"
        # Push a VLAN tag:
        # Only packets without a VLAN tag:
        # match = ofp_parser.OFPMatch()
        match = OFPMatch(in_port=primary_input_port,
                         eth_type=ether_types.ETH_TYPE_IP,  # ipv4_src=ip_pkt_src,
                         ipv4_dst=ip_pkt.dst)
        # match.set_ip_proto(ipv4.inet.IPPROTO_IP)
        tag = ofp_parser.OFPMatchField.make(
            ofp.OXM_OF_VLAN_VID, vlan_tag)
        actions = [ofp_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                   ofp_parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag))]

    elif datapath.id == sw_primary_tail:
        print "Pop a VLAN tag:\n\n\n\n"
        # Pop a VLAN tag:
        match = OFPMatch(in_port=primary_input_port,
                         vlan_vid=(0x1000 | vlan_tag), eth_type=ether_types.ETH_TYPE_IP,  # ipv4_src=ip_pkt_src,
                         ipv4_dst=ip_pkt.dst)
        actions = [ofp_parser.OFPActionPopVlan()]

    else:
        print "Forward the VLAN tag:\n\n\n\n"
        match = ofp_parser.OFPMatch(in_port=primary_input_port,
                                    vlan_vid=(0x1000 | vlan_tag))
        actions = []

    actions = [ofp_parser.OFPActionGroup(group_id)]



    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]


    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, ofp.OFPFC_ADD,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                primary_output_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    #print "Creating flow:",datapath.id,":",in_port,out_port,req
    datapath.send_msg(req)
    #create_group_mod_failover_flow(datapath,in_port,out_port,eth_pkt,ip_pkt,group_id)
#    create_group_mod_failover_flow(datapath, in_port, out_port, eth_pkt, ip_pkt, group_id)

def create_lb_select_flow(datapath, in_port, out_port, ip_pkt, group_id=1, msg=None, eth_pkt=None):
    ofp = datapath.ofproto
#    ofp.OFPP_IN_PORT
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 60
    #hard_timeout = 31
    hard_timeout = 3600
    priority = 32768
    data = None
    if msg != None:
        # Send the packet-In to the host:
        _send_packet(datapath, out_port, packet.Packet(msg.data))

        buffer_id = msg.buffer_id  # ofp.OFP_NO_BUFFER
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
    match = None
    if eth_pkt == None:
        match = OFPMatch( eth_type=ether_types.ETH_TYPE_IP, #ipv4_src=ip_pkt.src,
                          ipv4_dst=ip_pkt.dst)
    else:
        match = OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                        eth_dst = eth_pkt.dst,eth_src = eth_pkt.src,
                        #ipv4_src=ip_pkt.src,
                         ipv4_dst=ip_pkt.dst)

    #actions = [ofp_parser.OFPActionOutput(port=out_port)]
    #group_id = 1
    actions = [ofp_parser.OFPActionGroup(group_id)]

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, ofp.OFPFC_ADD,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst)
    print "Creating flow:",datapath.id,":",in_port,out_port,req
    datapath.send_msg(req)
    #create_group_mod_failover_flow(datapath,in_port,out_port,eth_pkt,ip_pkt,group_id)
#    create_group_mod_failover_flow(datapath, in_port, out_port, eth_pkt, ip_pkt, group_id)

def send_redirect_lb_to_server(datapath, in_port, out_port, ip_pkt, tcp_pkt, server_eth, server_ipv4,
                               lb_eth, lb_ipv4, tcp_src):
    #print "Aplicando Regra Client -> Servidor"
    #print "in_port %s out_port %s server_eth %s serverip %s lb_eth %s lb_ip%s"%(in_port, out_port, server_eth, server_ipv4, lb_eth, lb_ipv4)

    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 30
    #hard_timeout = 31
    hard_timeout = 3600
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    #match = ofp_parser.OFPMatch(in_port=4,eth_type=ether_types.ETH_TYPE_IP, eth_dst=lb_eth)

    match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=6,ipv4_src=ip_pkt.src,
                                ipv4_dst=lb_ipv4,tcp_src=tcp_pkt.src_port,tcp_dst=tcp_pkt.dst_port)#eth_dst=('00:00:00:00:00:FE'), eth_type=0x800,ipv4_dst='10.0.0.254',tcp_dst=0x0050)
    #match = ofproto_v1_3_parser.OFPMatch(eth_dst='00:00:00:00:00:FE')#,tcp_dst=0x0050)
                            #(in_port=in_port,eth_type=ether_types.ETH_TYPE_IP, eth_dst=lb_eth)

    actions = [ofp_parser.OFPActionSetField(eth_dst=server_eth)]
    actions.append(ofp_parser.OFPActionSetField(eth_src=lb_eth))

    actions.append(ofp_parser.OFPActionSetField(ipv4_src=lb_ipv4))
    #actions.append(ofp_parser.OFPActionSetField(tcp_src=tcp_src))
    actions.append(ofp_parser.OFPActionSetField(ipv4_dst=server_ipv4))
    #actions.append(ofp_parser.OFPActionSetField(tcp_src=tcp_dst))
    #actions.append(ofp_parser.OFPActionOutput(1, 0))
    actions.append(ofp_parser.OFPActionOutput(out_port, 0))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]

    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, ofp.OFPFC_ADD,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                #in_port, ofp.OFPG_ANY, <<<<<<<<<<<<<<<<<<<<<<<<<<<Verficar se estah ok!
                                out_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst,
                                # OFPFF_SEND_FLOW_REM 	Issues the Flow Removed message to the controller when this entry is deleted.
                                # OFPFF_CHECK_OVERLAP 	When the command is OFPFC_ADD, checks duplicated entries. If duplicated entries are found, Flow Mod fails and an error is returned.
                                # OFPFF_RESET_COUNTS 	Resets the packet counter and byte counter of the relevant entry.
                                # OFPFF_NO_PKT_COUNTS 	Disables the packet counter of this entry.
                                # OFPFF_NO_BYT_COUNTS 	Disables the byte counter of this entry.
                                flags= ofp.OFPFF_SEND_FLOW_REM|ofp.OFPFF_CHECK_OVERLAP)
    #print req
    datapath.send_msg(req)


def send_redirect_server_to_lb( datapath,in_port, out_port, ip_pkt, tcp_pkt, client_eth, client_ipv4,
                                                lb_eth, lb_ipv4):
    #print "Aplicando Regra Servidor -> Client"
    ofp = datapath.ofproto
    ofp_parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = 5
    hard_timeout = 3600
    #hard_timeout = 0
    priority = 32768
    buffer_id = ofp.OFP_NO_BUFFER
    #match = ofp_parser.OFPMatch(in_port=1,eth_type=ether_types.ETH_TYPE_IP, eth_dst=client_eth)
    match = ofp_parser.OFPMatch(in_port=in_port,eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=6,ipv4_dst=lb_ipv4, ipv4_src=ip_pkt.src, tcp_src= tcp_pkt.src_port,tcp_dst= tcp_pkt.dst_port)

    #print match
    actions = [ofp_parser.OFPActionSetField(eth_src=lb_eth)]
    #actions.append(ofp_parser.OFPActionSetField(eth_src=lb_eth))
    actions.append(ofp_parser.OFPActionSetField(eth_dst=client_eth))

    actions.append(ofp_parser.OFPActionSetField(ipv4_src=lb_ipv4))
    actions.append(ofp_parser.OFPActionSetField(ipv4_dst=client_ipv4))
    #actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0))
    #actions.append(ofp_parser.OFPActionOutput(4, 0))
    actions.append(ofp_parser.OFPActionOutput(out_port, 0))

    inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
    #print inst
    req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                table_id, ofp.OFPFC_ADD,
                                idle_timeout, hard_timeout,
                                priority, buffer_id,
                                in_port, ofp.OFPG_ANY,
                                ofp.OFPFF_SEND_FLOW_REM,
                                match, inst,# OFPFF_SEND_FLOW_REM 	Issues the Flow Removed message to the controller when this entry is deleted.
                                # OFPFF_CHECK_OVERLAP 	When the command is OFPFC_ADD, checks duplicated entries. If duplicated entries are found, Flow Mod fails and an error is returned.
                                # OFPFF_RESET_COUNTS 	Resets the packet counter and byte counter of the relevant entry.
                                # OFPFF_NO_PKT_COUNTS 	Disables the packet counter of this entry.
                                # OFPFF_NO_BYT_COUNTS 	Disables the byte counter of this entry.
                                flags= ofp.OFPFF_SEND_FLOW_REM|ofp.OFPFF_CHECK_OVERLAP)
    #print req

    datapath.send_msg(req)