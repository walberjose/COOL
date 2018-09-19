#!/usr/bin/python

"""
Custom topology for Mininet, generated by GraphML-Topo-to-Mininet-Network-Generator.
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Node
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections
import time

'''
sudo mn -c; sudo python ryu/app/COOL/mininet_topo/cycle-4.py

Remember to use "-O OpenFlow13" in all commands, such as: dpctl dump-groups -O OpenFlow13

To discover packet loss in TCP transmission use this filter in WireShark:
tcp.analysis.lost_segment or tcp.analysis.retransmission
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
        s3 = self.addSwitch( 's3' , protocols=["OpenFlow13"])

        # ... and now hosts
        s1_host = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        s2_host = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        # s3_host = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        # s4_host = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # add edges between switch and corresponding host
        self.addLink( s1 , s1_host)
        self.addLink( s2 , s2_host)
        # self.addLink( s1 , s3_host)
        # self.addLink( s3 , s4_host)

        # add edges between switches
        #Bandwidth limit 10000 is outside supported range 0..1000 - ignoring
        self.addLink( s1 , s2 , bw=100, delay='0.0ms') #Maximum of 1GB!
        self.addLink( s2 , s3 , bw=100, delay='0.0ms')
        self.addLink( s3 , s1 , bw=100, delay='0.0ms')
        # self.addLink( s4 , s1 , bw=1000, delay='0.0ms')


topos = { 'generated': ( lambda: GeneratedTopo() ) }

# HERE THE CODE DEFINITION OF THE TOPOLOGY ENDS

# the following code produces an executable script working with a remote controller
# and providing ssh access to the the mininet hosts from within the ubuntu vm
controller_ip = ''

def setupNetwork(controller_ip):
    "Create network and run simple performance test"
    # check if remote controller's ip was set
    # else set it to localhost
    topo = GeneratedTopo()
    if controller_ip == '':
        #controller_ip = '10.0.2.2';
        controller_ip = '127.0.0.1';
    net = Mininet(topo=topo, controller=lambda a: RemoteController( a, ip=controller_ip, port=6633 ), host=CPULimitedHost, link=TCLink)
    return net

def connectToRootNS( network, switch, ip, prefixLen, routes ):
    "Connect hosts to root namespace via switch. Starts network."
    "network: Mininet() network object"
    "switch: switch to connect to root namespace"
    "ip: IP address for root namespace node"
    "prefixLen: IP address prefix length (e.g. 8, 16, 24)"
    "routes: host networks to route to"
    # Create a node in root namespace and link to switch 0
    root = Node( 'root', inNamespace=False )
    intf = TCLink( root, switch ).intf1
    root.setIP( ip, prefixLen, intf )
    # Start network that now includes link to root namespace
    network.start()
    # Add routes from root ns to hosts
    for route in routes:
        root.cmd( 'route add -net ' + route + ' dev ' + str( intf ) )

def sshd( network, cmd='/usr/sbin/sshd', opts='-D' ):
    "Start a network, connect it to root ns, and run sshd on all hosts."
    switch = network.switches[ 0 ]  # switch to use
    ip = '10.123.123.1'  # our IP address on host network
    routes = [ '10.0.0.0/8' ]  # host networks to route to
    connectToRootNS( network, switch, ip, 8, routes )
    for host in network.hosts:
        host.cmd( cmd + ' ' + opts + '&' )

    # DEBUGGING INFO
    print
    print "Dumping host connections"
    dumpNodeConnections(network.hosts)
    print
    print "*** Hosts are running sshd at the following addresses:"
    print
    for host in network.hosts:
        print host.name, host.IP()
    print
    print "*** Type 'exit' or control-D to shut down network"
    print
    print "*** For testing network connectivity among the hosts, wait a bit for the controller to create all the routes, then do 'pingall' on the mininet console."
    print

    h1 = network.getNodeByName('h1')
    h2 = network.getNodeByName('h2')

    s1 = network.switches[ 0 ]  # switch to use 's1'
    s2 = network.switches[1]  # switch to use 's2'


    #time.sleep(3)

    count_up_and_down = 0
    number_of_interation = 1
    for i in range(0,number_of_interation):
        h2.cmd('iperf -s -u >> cycle-3/server-report.txt &')
        #print "Esperar 60 segundos..."
        #s1.cmd('ifconfig s1-eth2 up')
        #s1.cmd('ifconfig s1-eth2 up')
        print str(i)+'/'+str(number_of_interation)
        h1.cmd('ping 10.0.0.2 -c 3 ')
        h2.cmd('tcpdump -U -i h2-eth0 -s 65535 -w cycle-3/' + str(i) + '-dump.cap &')
        time.sleep(1)
        #s2.cmd('bwm-ng -o csv -c 0 | grep s2-eth1 > cycle-3/'+str(i)+'-s2-eth1-dump.csv ')
        #s2.cmd('bwm-ng -o csv -c 0 | grep s2-eth2 > cycle-3/' + str(i) + '-s2-eth2-dump.csv ')
        #time.sleep(5)
        h1.cmd('iperf -u -c 10.0.0.2 -t 30 -b 100M > cycle-3/client-measurement-'+str(i)+'.txt &')
        time.sleep(15)
        s1.cmd('ifconfig s1-eth2 down')
        time.sleep(15)
        #s1.cmd('ifconfig s1-eth2 up')
        h2.cmd('killall tcpdump')
        h2.cmd('killall iperf')
        h1.cmd('killall tcpdump')
        h1.cmd('killall iperf')
        #time.sleep(5)
        # if count_up_and_down % 2 == 0:
        #     s1.cmd('ifconfig s1-eth2 down')
        # else:
        #     s1.cmd('ifconfig s1-eth2 up')
        # count_up_and_down+=1
        # time.sleep(5)
        # time.sleep(10)
        # #h1.cmd('killall iperf')
        # time.sleep(5)





    #tcp.analysis.lost_segment or tcp.analysis.retransmission
    # h2.cmd('')
    # network.link()

    #CLI( network )
    for host in network.hosts:
        host.cmd( 'kill %' + cmd )
    network.stop()


if __name__ == '__main__':
    setLogLevel('info')
    #setLogLevel('debug')
    sshd( setupNetwork(controller_ip) )


#Important commands:
#Clean mininet:
# mn -c
#Shutdown a switch:
# switch s4 stop