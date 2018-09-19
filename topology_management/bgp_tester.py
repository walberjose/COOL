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

from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker

'''
sudo /usr/bin/python2.7 "/home/walber/Dropbox/SDN - Controllers/ryu/ryu/app/COOL/topology_management/bgp_tester.py"
'''

def dump_remote_best_path_change(event):
    print 'the best path changed:', event.remote_as, event.prefix,\
        event.nexthop, event.is_withdraw

def detect_peer_down(remote_ip, remote_as):
    print 'Peer down:', remote_ip, remote_as

if __name__ == "__main__":
    speaker = BGPSpeaker(as_number=65001, router_id='192.168.25.7',
                         best_path_change_handler=dump_remote_best_path_change,
                         peer_down_handler=detect_peer_down)

    speaker.neighbor_add('192.168.25.2', 65002)
    # uncomment the below line if the speaker needs to talk with a bmp server.
    # speaker.bmp_server_add('192.168.177.2', 11019)
    count = 1
    while True:
        print "Oi"
        eventlet.sleep(30)
        prefix = '10.20.' + str(count) + '.0/24'
        print "add a new prefix", prefix
        speaker.prefix_add(prefix)
        count += 1
        if count == 4:
            speaker.shutdown()
            break