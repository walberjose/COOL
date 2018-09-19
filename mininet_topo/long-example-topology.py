#!/usr/bin/python

"""
This example shows how to add an interface (for example a real
hardware interface) to a network after the network is created.
"""

import re
import sys

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import RemoteController,Host
from mininet.link import TCLink
#from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.nodelib import NAT

#Manipulate IP addresses
from netaddr import *

#Manipulate time
import time

'''
This topology works to investigate the LONG example of the manuscript: "Make Flows Great Again: a Hybrid Resilience Mechanism for OpenFlow Networks"

Remember to use "-O OpenFlow13" in all commands, such as: dpctl dump-flows "-O OpenFlow13"

sudo mn -c; sudo python ryu/app/COOL/mininet_topo/long-example-topology.py




Topology:

h1          s2        h4
    \    /      \   /
h2  - s1          s3- h5
    /   \        /  \
h3       s4-s5-s6     h6


'''


class GeneratedTopo( Topo ):
    "Internet Topology Zoo Specimen."

    def __init__( self, **opts ):
        "Create a topology."

        # Initialize Topology
        Topo.__init__( self, **opts )

        # add nodes, switches first...
        sA = self.addSwitch( 's1' , protocols=["OpenFlow13"])
        sB = self.addSwitch( 's2' , protocols=["OpenFlow13"])
        sC = self.addSwitch( 's3' , protocols=["OpenFlow13"])
        sD = self.addSwitch( 's4' , protocols=["OpenFlow13"])
        sE = self.addSwitch( 's5' , protocols=["OpenFlow13"])
        sF = self.addSwitch( 's6' , protocols=["OpenFlow13"])
        # s3 = self.addSwitch( 's3' , protocols=["OpenFlow13"])
        # s4 = self.addSwitch( 's4' , protocols=["OpenFlow13"])

        # ... and now hosts
        # s1_host = self.addHost('h1', ip='10.0.0.01/24', mac='00:00:00:00:00:01')
        # s2_host = self.addHost('h2', ip='10.0.0.02/24', mac='00:00:00:00:00:02')
        # s3_host = self.addHost('h3', ip='10.0.0.03/24', mac='00:00:00:00:00:03')
        #
        # s4_host = self.addHost('h4', ip='10.0.0.04/24', mac='00:00:00:00:00:04')
        # s5_host = self.addHost('h5', ip='10.0.0.05/24', mac='00:00:00:00:00:05')
        # s6_host = self.addHost('h6', ip='10.0.0.06/24', mac='00:00:00:00:00:06')

        list_of_hosts = []
        num_of_required_hosts = 1  # This number must be the same of num_of_required_hosts in topology_management.py
        final_host = self.addHost('h100', ip='10.0.0.100/24', mac='FE:00:00:00:00:FE')
        for i in range(1, num_of_required_hosts + 1):
            mac = EUI(i)
            mac.dialect = mac_unix
            host = self.addHost('h' + str(i), cls=Host, ip='10.0.0.' + str(i) + '/24', mac=mac)
            list_of_hosts.append(host)

        info('*** Add links\n')

        for host in list_of_hosts:
            self.addLink(sA, host, bw=1000, delay='0.0ms')

        # add edges between switch and corresponding host
        info('*** Add links of the topology\n')
        # Switch A to hosts and switches B and D
        self.addLink( sC , final_host, bw=1000, delay='0.0ms')


        # Making the remaining of the topology
        self.addLink( sA , sB   , bw=1000, delay='0.0ms')
        self.addLink( sB , sC   , bw=1000, delay='0.0ms')

        self.addLink(sA, sD, bw=1000, delay='0.0ms')
        self.addLink(sD, sE, bw=1000, delay='0.0ms')
        self.addLink(sE, sF, bw=1000, delay='0.0ms')
        self.addLink(sF, sC, bw=1000, delay='0.0ms')



topos = { 'generated': ( lambda: GeneratedTopo() ) }


# def checkIntf( intf ):
#     "Make sure intf exists and is not configured."
#     config = quietRun( 'ifconfig %s 2>/dev/null' % intf, shell=True )
#     if not config:
#         error( 'Error:', intf, 'does not exist!\n' )
#         exit( 1 )
#     ips = re.findall( r'\d+\.\d+\.\d+\.\d+', config )
#     if ips:
#         error( 'Error:', intf, 'has an IP address,'
#                'and is probably in use!\n' )
#         exit( 1 )

if __name__ == '__main__':
    simple_linear_2links = GeneratedTopo()

    setLogLevel( 'info' )

    # try to get hw intf from the command line; by default, use server1
    #intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'server1'
    #info( '*** Connecting to hw intf: %s' % intfName )

    #info( '*** Checking', intfName, '\n' )
    #checkIntf( intfName )

    info( '*** Creating network\n' )
    controller = RemoteController('c0',ip='127.0.0.1', port=6633)
    net = Mininet(simple_linear_2links, controller=controller, link=TCLink)#topo=TreeTopo( depth=1, fanout=2 ) )

    # s1 = net.switches[0]
    # _intf_linkC = Intf('linkC', node=s1)
    # _intf_linkB = Intf('linkB', node=s1)
    # _intf_linkA = Intf('linkA', node=s1)
    #_intf_link8 = Intf('link8', node=s1)


    #net.addNAT().configDefault()
    #_intf_link8 = Intf('wlan0', node=s1)
    # switch = net.switches[ 0 ]
    # info( '*** Adding hardware interface', intfName, 'to switch',
    #       switch.name, '\n' )
    # _intf = Intf( intfName, node=switch )

    info( '*** Note: you may need to reconfigure the interfaces for '
          'the Mininet hosts:\n', net.hosts, '\n' )

    #net.addNAT().configDefault()
    net.start()
    # cmd = 'route add default gw 10.0.0.1'
    # for host in net.hosts:
    #     host.cmd( cmd )#+ ' ' + opts + '&' )
        # if host.name == "nat1":
        #     host.cmd('nat1 route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.1.2')
    CLI( net )
    # s2 = net.getNodeByName('s2')
    # s2.cmd('tcpdump -i s2-eth0 -w s2-eth0.cap &')
    #
    # s4 = net.getNodeByName('s4')
    # s4.cmd('tcpdump -i s4-eth0 -w s4-eth0.cap &')
#LONG: automatic experiments:
    # h100 = net.getNodeByName('h100')
    # h100.cmd('iperf -s -i 0.001 -y C -D > server.csv&')
    # h100.cmd('tcpdump -U -i h100-eth0 -w test.cap &')
    # start = time.time()
    # #h100.cmd('ping 10.0.0.1 -c &')
    # info( '*** Pinging...\n')
    # time.sleep(5)
    # h100.cmd('ping -c 1 10.0.0.1')
    # time.sleep(3)
    # for host in net.hosts:
    #     if host.name == "h100":
    #         pass
    #     else:
    #         if host.name == 'h1':
    #             host.cmd('tcpdump -U -i h1-eth0 -w test-h1-eth0.cap &')
    #         host.cmd('iperf -c 10.0.0.100&')
    #         #host.cmd('ping -f 10.0.0.100 -c 100000&')
    # time.sleep(1)
    # #Simulate a failure between s2 (switch B) and s3 (switch C)
    # info('*** Simulating a broken link ...\n')
    # info('Broken link in '+str(start)+" duration:"+str(time.time()-start))
    # #h100.cmd('wget 10.0.0.1 &')
    # s2 = net.getNodeByName('s2')
    # s2.cmd('ifconfig s2-eth1 down')
    # time.sleep(3)
    net.stop()