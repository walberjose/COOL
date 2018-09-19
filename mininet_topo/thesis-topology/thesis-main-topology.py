#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call


'''
sudo mn -c; sudo python ryu/app/COOL/mininet_topo/thesis-topology/thesis-main-topology.py

TODO: Falta conectar os hosts r1,r2 e r3 via gobgp

                        2.2.2.0/24
                                            6.6.6.0/24
                     .2  AS 2   ----    AS 6    
      1.1.2.0/24     /        .1\        /.2 
                .1  /   2.2.3.0/24\     /.1
1.1.1.0/24        AS 1           .2 AS 3    3.3.3.0/24
                .1  \                /.2
      1.1.4.0/24   .2\              /.1
                    AS 4  --   AS 5
                4.4.4.0/24          5.5.5.0/24            
            
            
AS 2:
-> AS de transito
-> Implementa a solucao proposta

AS 3:
-> Tier 2
-> Gerador/Transito de conteudo nacional

AS 6:
-> Tier 1
-> Gerador/Transito de conteudo internacional 

 
'''

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class COOL_topology(Topo):

    def __init__(self, **opts ):
        # Initialize Topology
        Topo.__init__(self, **opts)

        # info('*** Add switches\n')
        # s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
        # s1 = self.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')

        # info('*** Add hosts\n')
        # h4 = self.addHost('h4', cls=Host, ip='192.168.2.4/24', defaultRoute='via 192.168.2.254', mac='00:00:00:00:00:04')
        # h5 = self.addHost('h5', cls=Host, ip='192.168.2.5/24', defaultRoute='via 192.168.2.254', mac='00:00:00:00:00:05')
        # h6 = self.addHost('h6', cls=Host, ip='192.168.2.6/24', defaultRoute='via 192.168.2.254', mac='00:00:00:00:00:06')

        # r2 = self.addHost('r2', cls=LinuxRouter, ip='10.0.2.2/24', defaultRoute='via 10.0.2.254', mac='00:00:00:00:00:02')
        # r1 = self.addHost('r1', cls=LinuxRouter, ip='10.0.1.1/24', defaultRoute='via 10.0.1.254', mac='00:00:00:00:00:01')
        routers = {}
        switches = {}
        for id in range(1,7):
            routers[id] = self.addHost('r'+str(id), cls=LinuxRouter, ip=str(id)+"."+str(id)+"."+str(id)+"."+'0/24',
                          mac='00:00:00:00:00:0'+str(id))
            switches[id] = self.addSwitch('s'+str(id), cls=OVSKernelSwitch, failMode='standalone')

        # r3 = self.addHost('r3', cls=LinuxRouter, ip='192.168.25.24/24', defaultRoute='via 192.168.25.100',
        #                   mac='00:00:00:00:00:03')

        info('*** Add links\n')
        self.addLink(routers[1], switches[1], intfName1='r1-eth1', params1={'ip': '1.1.2.1/24'},
                     intfName2='s1-eth0', params2={'ip': '1.1.2.2/24'}, bw=10, delay='0.0ms')
        info('*** Finished adding links\n')

        # self.addLink(routers[1], routers[2],intfName1='r1-eth1',params1={ 'ip' : '1.1.2.1/24' },
        #                     intfName2='r2-eth0', params2={ 'ip' : '1.1.2.2/24' } , bw=10, delay='0.0ms')
        # self.addLink(routers[1], routers[4], bw=10, delay='0.0ms')
        # self.addLink(routers[2], routers[3], bw=10, delay='0.0ms')
        # self.addLink(routers[2], routers[6], bw=10, delay='0.0ms')
        # self.addLink(routers[4], routers[5], bw=10, delay='0.0ms')
        # self.addLink(routers[3], routers[6], bw=10, delay='0.0ms')
        # self.addLink(routers[5], routers[3], bw=10, delay='0.0ms')
        #self.addLink(s1, r1, intfName2='r1-eth1', params2={'ip': '172.16.0.1/24'}, bw=10, delay='0.0ms')
        #self.addLink(s1, r2, intfName2='r2-eth1', params2={'ip': '172.16.0.2/24'}, bw=10, delay='0.0ms')
        #self.addLink(s1, r3, bw=10, delay='0.0ms')

        # info('*** Starting network\n')
        # self.build()
        # info('*** Starting controllers\n')
        # for controller in self.controllers:
        #     controller.start()
        #
        # info('*** Starting switches\n')
        # self.get('s2').start([c0])
        # self.get('s1').start([])
        #
        # info('*** Post configure switches and hosts\n')
        # for host in self.hosts:
        #     if host.name == 'h2':
        #         host.cmd('ifconfig h2-eth1 172.16.0.2 netmask 255.255.255.0')
        #     if host.name == 'h1':
        #         host.cmd('ifconfig h1-eth1 172.16.0.1 netmask 255.255.255.0')
        #     pass
        #
        # CLI(net)
        # net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    cool_topology = COOL_topology()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=cool_topology, controller=c0, host=CPULimitedHost,
                  link=TCLink)

    # Add NAT connectivity
    natIP = '10.0.254.1/24'
    # nat0 = net.addNAT('nat0', ip=natIP, connect=net.get('r2'), localIntf='lxcbr0',mac='00:00:00:00:00:07',
    #                   inNamespace=False,params={'ip':"172.16.0.4/24"})
    #net.addLink(nat0, net.get('s2'))

    #Building network:
    info('*** Building network\n')
    net.start()
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Post configure switches and hosts\n')
    # for host in net.hosts:
    #     host.cmd('./ryu/app/COOL/mininet_topo/thesis-topology/'+str(host)+)
    #     if host.name == 'h4':
    #         host.cmd('route add default gw 192.168.2.254')
    #     if host.name == 'h5':
    #         host.cmd('route add default gw 192.168.2.254')
    #     if host.name == 'h6':
    #         host.cmd('route add default gw 192.168.2.254')
    #     if host.name == 'r3':
    #         host.cmd('ifconfig r3-eth0 172.16.0.3 netmask 255.255.255.0')
    #         host.cmd('iperf -u -s &')
    #         #Without VM:
    #         host.cmd('route add -net 10.0.1.0 netmask 255.255.255.0 gw 172.16.0.1')
    #         host.cmd('route add -net 10.0.2.0 netmask 255.255.255.0 gw 172.16.0.2')
    #         host.cmd('route add default gw 172.16.0.2')
    #         host.cmd('/usr/lib/go/bin/gobgpd -f ryu/app/COOL/mininet_topo/r3/r3-go-config.conf &')
    #     if host.name == 'r2':
    #         host.cmd('ifconfig r2-eth1 172.16.0.2 netmask 255.255.255.0')
    #         host.cmd('/usr/lib/go/bin/gobgpd -f ryu/app/COOL/mininet_topo/r2/r2-go-config.conf &')
    #         # Without VM:
    #         host.cmd('route add default gw 10.0.2.254')
    #     if host.name == 'r1':
    #         host.cmd('ifconfig r1-eth1 172.16.0.1 netmask 255.255.255.0')
    #         host.cmd('/usr/lib/go/bin/gobgpd -f ryu/app/COOL/mininet_topo/r1/r1-go-config.conf &')
    #         # Without VM:
    #         host.cmd('route add default gw 10.0.1.254')
    #     if host.name == 'nat0':
    #         host.cmd('ifconfig nat0-eth0 hw ether 00:00:00:00:00:07 10.0.254.1 netmask 255.255.255.0')
    #         host.cmd('route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.254.254')
    #         host.cmd('route add -net 10.0.2.0 netmask 255.255.255.0 gw 10.0.254.254')
    #         host.cmd('route add -net 172.16.0.0 netmask 255.255.255.0 gw 10.0.254.254')

    info('*** Starting switches\n')


    #intfName = 'virbr0'
    #switch = net.get('s2')#net.switches[0]
    # info('*** Adding hardware interface', intfName, 'to switch',
    #      switch.name, '\n')
    #_intf = Intf(intfName, node=switch)

    #Used to avoid s1 be out of failMode:
    # net.get('s2').start([c0])
    # net.get('s1').start([])
    #print net.get('s1').failMode, "<<<<<<<<<<<<<<<<"
    #net.get('s1').failMode = 'standalone'
    #print net.get('s1').failMode, "<<<<<<<<<<<<<<<<"

    for host in net.hosts:

        if host.name[0] == 'h':
            print "Oi",host.name
            # if host.name == 'h6':
            #     host.cmd('sleep 10; ping 172.16.0.3 -c 30 &')
            # else:
            #     host.cmd('ping 172.16.0.3 -c 30 &')
            #host.cmd('iperf -u -s 172.16.0.3 -b 5M')


    CLI(net)
    net.stop()


# def myNetwork():
#
#     net = Mininet( topo=None,
#                    build=False,
#                    ipBase='10.0.0.0/8')
#
#     info( '*** Adding controller\n' )
#     c0=net.addController(name='c0',
#                       controller=RemoteController,
#                       ip='127.0.0.1',
#                       protocol='tcp',
#                       port=6633)

    # info( '*** Add switches\n')
    # s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    # s1 = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')
    #
    # info( '*** Add hosts\n')
    # h4 = net.addHost('h4', cls=Host, ip='192.168.2.4/24', defaultRoute='via 192.168.2.254',mac='00:00:00:00:00:04')
    # h5 = net.addHost('h5', cls=Host, ip='192.168.2.5/24', defaultRoute='via 192.168.2.254',mac='00:00:00:00:00:05')
    # h6 = net.addHost('h6', cls=Host, ip='192.168.2.6/24', defaultRoute='via 192.168.2.254',mac='00:00:00:00:00:06')
    #
    # r2 = net.addHost('r2', cls=LinuxRouter, ip='10.0.2.2', defaultRoute='via 10.0.2.254', mac='00:00:00:00:00:02')
    # r1 = net.addHost('r1', cls=LinuxRouter, ip='10.0.1.1', defaultRoute='via 10.0.1.254', mac='00:00:00:00:00:01')
    #
    # r3 = net.addHost('r3', cls=LinuxRouter, ip='172.16.0.3', defaultRoute='via 172.16.0.2', mac='00:00:00:00:00:03')
    #
    # info( '*** Add links\n')
    #
    # net.addLink(s2, r1, bw=10, delay='0.0ms')
    # net.addLink(s2, r2, bw=10, delay='0.0ms')
    # net.addLink(s2, h5, bw=10, delay='0.0ms')
    # net.addLink(s2, h4, bw=10, delay='0.0ms')
    # net.addLink(s2, h6, bw=10, delay='0.0ms')
    # net.addLink(s1, r1, intfName2='r1-eth1', params2={ 'ip' : '172.16.0.1/24' }, bw=10, delay='0.0ms' )
    # net.addLink(s1, r2, intfName2='r2-eth1', params2={ 'ip' : '172.16.0.2/24' }, bw=10, delay='0.0ms' )
    # net.addLink(s1, r3, bw=10, delay='0.0ms')
    #
    # info( '*** Starting network\n')
    # net.build()
    # info( '*** Starting controllers\n')
    # for controller in net.controllers:
    #     controller.start()
    #
    # info( '*** Starting switches\n')
    # net.get('s2').start([c0])
    # net.get('s1').start([])
    #
    # info( '*** Post configure switches and hosts\n')
    # for host in net.hosts:
    #     if host.name == 'h2':
    #         host.cmd('ifconfig h2-eth1 172.16.0.2 netmask 255.255.255.0')
    #     if host.name == 'h1':
    #         host.cmd('ifconfig h1-eth1 172.16.0.1 netmask 255.255.255.0')
    #     pass
    #
    # CLI(net)
    # net.stop()

# if __name__ == '__main__':
#     setLogLevel( 'info' )
#     myNetwork()