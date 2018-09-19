import bz2
import gzip
from ryu.lib import mrtlib

# count = 0
# with gzip.open("bview.20180102.1600.gz","r") as bgp_update:
#     for record in mrtlib.Reader(bgp_update):
#         print("%d, %s" % (count, record))
#         count += 1
#         break
#
# count = 0
# with gzip.open("updates.20180102.2025.gz","r") as bgp_update:
#     for record in mrtlib.Reader(bgp_update):
#         print("%d, %s" % (count, record))
#         count += 1
#         break

#Bgp4MpMrtRecord(length=163,message=Bgp4MpMessageAs4MrtMessage(afi=1,bgp_message=BGPUpdate(len=143,nlri=[BGPNLRI(addr='62.220.112.0',length=21), BGPNLRI(addr='87.107.128.0',length=17), BGPNLRI(addr='87.107.120.0',length=24), BGPNLRI(addr='87.107.121.0',length=24), BGPNLRI(addr='87.107.43.0',length=24), BGPNLRI(addr='87.107.92.0',length=23), BGPNLRI(addr='87.107.124.0',length=22), BGPNLRI(addr='87.107.72.0',length=21), BGPNLRI(addr='87.107.64.0',length=19)],path_attributes=[BGPPathAttributeOrigin(flags=64,length=1,type=1,value=0), BGPPathAttributeAsPath(flags=64,length=70,type=2,value=[[22548, 16735, 12956, 701, 3257, 12880, 12880, 12880, 12880, 12880, 12880, 12880, 12880, 12880, 12880, 12880, 21341]]), BGPPathAttributeNextHop(flags=64,length=4,type=3,value='187.16.217.17')],total_path_attribute_len=84,type=2,withdrawn_routes=[],withdrawn_routes_len=0),if_index=0,local_as=12654,local_ip='187.16.216.23',peer_as=22548,peer_ip='187.16.217.17'),subtype=4,timestamp=1320105509,type=16)

count = 0

ASES = {}
with open("updates.20111031.2355","r") as bgp_update:
    for record in mrtlib.Reader(bgp_update):
        if record.subtype == mrtlib.Bgp4MpMrtRecord.SUBTYPE_BGP4MP_STATE_CHANGE_AS4:
            continue
        #print dir(record),"<<<<<<<<<<",record.subtype, record
        if record.message.bgp_message:
            #print dir(record.message.bgp_message),"\n|\n",record.message.bgp_message.type#.path_attributes#[1].value[0][-1]
            if record.message.bgp_message.type == mrtlib.bgp.BGP_MSG_UPDATE:
                if record.message.bgp_message.nlri == []:
                    continue
                #print "UPDATE"
                #print record.message.bgp_message,"kkkkkkkkkkkkk"
                for path_attr in record.message.bgp_message.path_attributes:
                    #print path_attr
                    if path_attr.type == mrtlib.bgp.BGP_ATTR_TYPE_AS_PATH:
                        as_path = path_attr.value[0]
                        #print dir(path_attr), "\n|\n",\
                        #print as_path,"<<<<",record.message.bgp_message.nlri  # .path_attributes#[1].value[0][-1]
                        as_origin = as_path[-1]
                        if as_origin not in ASES:
                            ASES[as_origin] = {'as_paths':[{'as_path':as_path,'nlri':record.message.bgp_message.nlri}]}#record.message.bgp_message.nlri}
                        else:
                            ASES[as_origin]['as_paths'].append({'as_path':as_path,'nlri':record.message.bgp_message.nlri})#record.message.bgp_message.nlri)


            if record.message.bgp_message.type == mrtlib.bgp.BGP_MSG_KEEPALIVE:
                pass
                #print record.message.bgp_message,"KEEP ALIVE","AQUIIIIIIIII"

            #print("%d, %s" % (count, record))
            count += 1
            # if count == 30:
            #     break

for asn in ASES:
     #print asn, ASES[asn]['as_paths']
     network_neighbors = {}
     for index,paths in enumerate(ASES[asn]['as_paths']):
         neighbor = paths['as_path'][0]
         as_nlri = paths['nlri']
         if neighbor not in network_neighbors:
             network_neighbors[neighbor] = [as_nlri]
         else:
             network_neighbors[neighbor].append(as_nlri)
             # if neighbor[as_path] == as_nlri:
             #     pass
             # else:
             #
             #     print neighbor[as_path],"OI",as_nlri
     #Origin <-> Number of neighbors
     print asn,len(network_neighbors),network_neighbors.keys()


# Debugging: 8402 [
# 	{'as_path': [19089, 12989, 3549, 3216, 8402], 'nlri': [BGPNLRI(addr='93.81.195.0',length=24), BGPNLRI(addr='93.81.34.0',length=24), BGPNLRI(addr='95.31.142.0',length=24), BGPNLRI(addr='89.179.200.0',length=24)]},
# 	{'as_path': [19089, 12989, 1273, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.178.0',length=24), BGPNLRI(addr='78.106.223.0',length=24), BGPNLRI(addr='95.29.217.0',length=24), BGPNLRI(addr='95.29.39.0',length=24), BGPNLRI(addr='89.179.79.0',length=24), BGPNLRI(addr='93.81.165.0',length=24)]},
# 	{'as_path': [16735, 12989, 1273, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.217.0',length=24), BGPNLRI(addr='78.106.223.0',length=24), BGPNLRI(addr='89.179.79.0',length=24), BGPNLRI(addr='95.29.39.0',length=24), BGPNLRI(addr='95.29.178.0',length=24), BGPNLRI(addr='93.81.165.0',length=24)]},
# 	{'as_path': [19089, 12989, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.178.0',length=24), BGPNLRI(addr='93.81.195.0',length=24), BGPNLRI(addr='78.106.223.0',length=24), BGPNLRI(addr='95.29.217.0',length=24), BGPNLRI(addr='93.81.34.0',length=24), BGPNLRI(addr='95.31.142.0',length=24), BGPNLRI(addr='89.179.200.0',length=24), BGPNLRI(addr='95.29.39.0',length=24), BGPNLRI(addr='89.179.79.0',length=24), BGPNLRI(addr='93.81.165.0',length=24)]},
# 	{'as_path': [19089, 12989, 31133, 8402], 'nlri': [BGPNLRI(addr='2.93.124.0',length=24), BGPNLRI(addr='78.106.138.0',length=24), BGPNLRI(addr='2.94.75.0',length=24), BGPNLRI(addr='2.94.145.0',length=24), BGPNLRI(addr='2.92.124.0',length=24), BGPNLRI(addr='2.94.143.0',length=24), BGPNLRI(addr='2.92.37.0',length=24), BGPNLRI(addr='78.106.66.0',length=24), BGPNLRI(addr='2.94.175.0',length=24), BGPNLRI(addr='2.92.71.0',length=24)]},
# 	{'as_path': [19089, 12989, 20562, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.227.0',length=24)]},
# 	{'as_path': [19089, 7162, 10429, 12956, 1299, 31133, 8402], 'nlri': [BGPNLRI(addr='89.179.79.0',length=24), BGPNLRI(addr='2.94.145.0',length=24), BGPNLRI(addr='78.106.138.0',length=24), BGPNLRI(addr='95.29.39.0',length=24), BGPNLRI(addr='93.81.165.0',length=24), BGPNLRI(addr='2.92.124.0',length=24), BGPNLRI(addr='78.106.223.0',length=24), BGPNLRI(addr='2.92.37.0',length=24), BGPNLRI(addr='2.92.71.0',length=24), BGPNLRI(addr='93.81.195.0',length=24), BGPNLRI(addr='2.94.75.0',length=24), BGPNLRI(addr='93.81.34.0',length=24), BGPNLRI(addr='2.94.175.0',length=24), BGPNLRI(addr='95.29.178.0',length=24), BGPNLRI(addr='95.29.217.0',length=24), BGPNLRI(addr='89.179.200.0',length=24), BGPNLRI(addr='2.93.124.0',length=24), BGPNLRI(addr='78.106.66.0',length=24), BGPNLRI(addr='2.94.143.0',length=24), BGPNLRI(addr='95.31.142.0',length=24)]},
# 	{'as_path': [16735, 12989, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.217.0',length=24), BGPNLRI(addr='95.29.178.0',length=24), BGPNLRI(addr='93.81.165.0',length=24), BGPNLRI(addr='95.29.39.0',length=24), BGPNLRI(addr='89.179.79.0',length=24), BGPNLRI(addr='93.81.34.0',length=24), BGPNLRI(addr='78.106.223.0',length=24), BGPNLRI(addr='95.31.142.0',length=24), BGPNLRI(addr='89.179.200.0',length=24), BGPNLRI(addr='93.81.195.0',length=24)]},
# 	{'as_path': [16735, 12989, 2828, 1299, 31133, 8402], 'nlri': [BGPNLRI(addr='2.94.75.0',length=24), BGPNLRI(addr='2.94.143.0',length=24), BGPNLRI(addr='2.92.71.0',length=24), BGPNLRI(addr='78.106.138.0',length=24), BGPNLRI(addr='2.92.37.0',length=24), BGPNLRI(addr='2.94.145.0',length=24), BGPNLRI(addr='2.92.124.0',length=24), BGPNLRI(addr='2.93.124.0',length=24), BGPNLRI(addr='2.94.175.0',length=24), BGPNLRI(addr='78.106.66.0',length=24)]},
# 	{'as_path': [16735, 3549, 31133, 8402], 'nlri': [BGPNLRI(addr='2.93.124.0',length=24), BGPNLRI(addr='78.106.138.0',length=24), BGPNLRI(addr='2.94.143.0',length=24), BGPNLRI(addr='2.92.71.0',length=24), BGPNLRI(addr='2.94.175.0',length=24), BGPNLRI(addr='78.106.66.0',length=24), BGPNLRI(addr='2.92.37.0',length=24), BGPNLRI(addr='2.94.75.0',length=24), BGPNLRI(addr='2.94.145.0',length=24), BGPNLRI(addr='2.92.124.0',length=24)]},
# 	{'as_path': [16735, 12989, 20562, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.227.0',length=24)]},
# 	{'as_path': [19089, 12989, 1273, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.227.0',length=24)]},
# 	{'as_path': [19089, 12989, 3549, 3216, 8402], 'nlri': [BGPNLRI(addr='2.94.39.0',length=24), BGPNLRI(addr='95.29.28.0',length=24), BGPNLRI(addr='93.81.55.0',length=24), BGPNLRI(addr='2.94.227.0',length=24), BGPNLRI(addr='93.81.182.0',length=24), BGPNLRI(addr='95.31.51.0',length=24), BGPNLRI(addr='78.106.30.0',length=24), BGPNLRI(addr='78.106.24.0',length=24), BGPNLRI(addr='93.81.8.0',length=24), BGPNLRI(addr='78.106.228.0',length=24), BGPNLRI(addr='93.81.63.0',length=24), BGPNLRI(addr='78.106.26.0',length=24)]},
# 	{'as_path': [19089, 12989, 3549, 3216, 8402], 'nlri': [BGPNLRI(addr='176.15.79.0',length=24)]},
# 	{'as_path': [19089, 12989, 3216, 8402], 'nlri': [BGPNLRI(addr='2.94.39.0',length=24), BGPNLRI(addr='95.29.28.0',length=24), BGPNLRI(addr='2.94.227.0',length=24), BGPNLRI(addr='95.31.51.0',length=24), BGPNLRI(addr='78.106.30.0',length=24), BGPNLRI(addr='176.15.79.0',length=24), BGPNLRI(addr='78.106.24.0',length=24), BGPNLRI(addr='78.106.26.0',length=24)]},
# 	{'as_path': [19089, 12989, 3216, 8402], 'nlri': [BGPNLRI(addr='95.29.227.0',length=24), BGPNLRI(addr='93.81.55.0',length=24), BGPNLRI(addr='93.81.182.0',length=24), BGPNLRI(addr='93.81.8.0',length=24), BGPNLRI(addr='78.106.228.0',length=24), BGPNLRI(addr='93.81.63.0',length=24)]},
# 	{'as_path': [19089, 12989, 3216, 8402], 'nlri': [BGPNLRI(addr='2.94.39.0',length=24), BGPNLRI(addr='95.29.28.0',length=24), BGPNLRI(addr='2.94.227.0',length=24), BGPNLRI(addr='95.31.51.0',length=24), BGPNLRI(addr='78.106.30.0',length=24), BGPNLRI(addr='176.15.79.0',length=24), BGPNLRI(addr='78.106.24.0',length=24), BGPNLRI(addr='78.106.26.0',length=24)]}]
