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
from mininet.node import RemoteController
from mininet.link import TCLink
#from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.nodelib import NAT


'''
IT DOES NOT WORK APPROPRIATE BECAUSE NX DOES NOT RECOGNIZE TWO LINKS BETWEEN A PAIR OF NODES. It treats as the same.

sudo python ryu/app/COOL/mininet_topo/simple_linear_2links.py
'''


class GeneratedTopo( Topo ):
    "Internet Topology Zoo Specimen."

    def __init__( self, **opts ):
        "Create a topology."

        # Initialize Topology
        Topo.__init__( self, **opts )

        # add nodes, switches first...
        s1 = self.addSwitch( 's1' , protocols=["OpenFlow13"])
        s2 = self.addSwitch( 's2' , protocols=["OpenFlow13"])
        # s3 = self.addSwitch( 's3' , protocols=["OpenFlow13"])
        # s4 = self.addSwitch( 's4' , protocols=["OpenFlow13"])

        # ... and now hosts
        h1_host = self.addHost('h1', ip='10.0.0.01/24', mac='00:00:00:00:00:01')
        h2_host = self.addHost('h2', ip='10.0.0.02/24', mac='00:00:00:00:00:02')
        h3_host = self.addHost('h3', ip='10.0.0.03/24', mac='00:00:00:00:00:03')

        # add edges between switch and corresponding host
        self.addLink( s1 , h1_host, bw=10, delay='0.0ms')
        self.addLink( s2 , h2_host, bw=10, delay='0.0ms')
        self.addLink( s2 , h3_host, bw=10, delay='0.0ms')
        self.addLink( s1 , s2, bw=10, delay='0.0ms')
        self.addLink( s1 , s2, bw=10, delay='0.0ms')

        #you can call addHost(cls=NAT...) directly if you don't like addNAT() - addNAT() is just a convenience method
        #self.natIP = '10.0.0.1/24'#kwargs.pop('natIP', '10.0.0.254')
        #self.connect = kwargs.pop('connect', 's1')
        #self.hopts.update(defaultRoute='via ' + self.natIP)
        #nat0 = self.addNode('nat0', cls=NAT, ip='10.0.0.1/24', inNamespace=False)
        #self.addLink(s1, nat0)

        # add edges between switches
        # self.addLink( s1 , s2 , bw=10, delay='0.0ms')
        # self.addLink( s2 , s3 , bw=10, delay='0.0ms')
        # self.addLink( s3 , s4 , bw=10, delay='0.0ms')
        # self.addLink( s4 , s1 , bw=10, delay='0.0ms')

        #intfName = sys.argv[1] if len(sys.argv) > 1 else 'server1'



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
    net.stop()