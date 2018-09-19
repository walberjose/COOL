import json
from webob import Response
import requests
import math


from _pybgpstream import BGPStream, BGPRecord, BGPElem

from collections import defaultdict



class RIPE_database():
    '''
        The exact links for each of the datasets are as follows:
        '''
    DATASET = ['ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
               'ftp.ripe.net/ripe/stats/delegated-ripencc-latest',
               'ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest',
               'ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest',
               'ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest']

    # PS: The ASN descriptions are based on data obtained from cidr-report.
    # http://ftp.lacnic.net/pub/stats/lacnic/RIR-Statistics-Exchange-Format.txt
    def __init__(self):
        pass


def getting_BGP_update():
    stream = BGPStream()
    rec = BGPRecord()
    stream.add_filter('collector', 'rrc11')
    stream.add_interval_filter(1438417216, 1438417216)
    # Start the stream
    stream.start()
    while (stream.get_next_record(rec)):
        if rec.status != "valid":
            print rec.project, rec.collector, rec.type, rec.time, rec.status
        else:
            elem = rec.get_next_elem()
            while (elem):
                print rec.project, rec.collector, rec.type, rec.time, rec.status,
                print elem.type, elem.peer_address, elem.peer_asn, elem.fields
                elem = rec.get_next_elem()


def MOAS_prefixes():
    # Create a new bgpstream instance and a reusable bgprecord instance
    stream = BGPStream()
    rec = BGPRecord()

    # Consider Route Views Singapore only
    stream.add_filter('collector', 'route-views.sg')

    # Consider RIBs dumps only
    stream.add_filter('record-type', 'ribs')

    # Consider this time interval:
    # Sat, 01 Aug 2015 7:50:00 GMT -  08:10:00 GMT
    stream.add_interval_filter(1438415400, 1438416600)

    # Start the stream
    stream.start()

    # <prefix, origin-ASns-set > dictionary
    prefix_origin = defaultdict(set)
    prefix_origin_dict = defaultdict(list)

    # Get next record
    while (stream.get_next_record(rec)):
        elem = rec.get_next_elem()
        while (elem):
            # Get the prefix
            pfx = elem.fields['prefix']
            # Get the list of ASes in the AS path
            ases = elem.fields['as-path'].split(" ")
            if len(ases) > 0:
                # Get the origin ASn (rightmost)
                origin = ases[-1]
                if 262857 == origin:#AS262857 - UFRN: AS262857 	177.20.128.0/19 	UNIVERSIDADE FEDERAL DO RIO GRANDE DO NORTE
                    '''
                    BI 	177.20.128.0/19 	198.32.125.84 	280 	100 	0 	1916, 262857 	IGP
                    E 	177.20.128.0/19 	213.248.67.117 	0 	70 	0 	1299, 2914, 1916, 262857 	IGP
                    E 	177.20.128.0/19 	213.248.98.93 	0 	70 	0 	1299, 2914, 1916, 262857 	IGP
                    '''
                    print "Achou UFRN"
                # Insert the origin ASn in the set of
                # origins for the prefix
                prefix_origin[pfx].add(origin)
                prefix_origin_dict[pfx].append(ases)

            elem = rec.get_next_elem()

    # Print the list of MOAS prefix and their origin ASns
    for pfx in prefix_origin:
        if len(prefix_origin[pfx]) > 1:
            pass #print pfx, ",".join(prefix_origin[pfx])
            #print pfx, prefix_origin_dict[pfx],"<<<< AS-Path"


def extract_prefix_IPv4(url):
    response = requests.get(url)
    listOfLines = str(response.content).split('\n')
    for line in listOfLines:
        # if line.find("asn") == 0:
        #     continue
        listOfRegisters = line.split('|')
        if len(listOfRegisters) != 7:
            continue
        if listOfRegisters[2] == 'ipv4':
            #print line

            #Prefix:
            prefix = listOfRegisters[3]
            #Netmask:
            netmask = int(32-math.log(float(listOfRegisters[4]),2)) # 256 to /24
            #ASN:
            print prefix,"/",netmask
            #ASN = listOfRegisters[]

if __name__ == '__main__':
    #https: // rest.db.ripe.net / {source} / {objecttype} / {key}
    # for i in range(1,33):
    #     print i,int(math.log(2**(i),2))

    url = 'http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'
    #extract_prefix_IPv4(url)
    #(Prefix_{src}, ASN_{src}, Prefix_{dst}, ASN_{dst})
    #policy_object = {'prefix_src':'10.0.0.1', 'asn_src':12, 'prefix_dst':'10.0.0.2', 'asn_dst':2}

    #getting_BGP_update()
    #MOAS_prefixes()

    # response = requests.get(url)
    # print response, response.content#json()

    "lacnic|AR|ipv4|24.232.0.0|65536|19970602|allocated"