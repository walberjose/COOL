# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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



from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response


'''
sudo PYTHONPATH=. ./bin/ryu-manager  --enable-debugger --observe-links  --verbose ryu/app/sdnip/topology_management/topo_discover_13.py
'''

#simple_switch_api_app = 'cool_interface'
simple_switch_instance_name = 'cool_interface'
url = '/simpleswitch/'

class COOL_Interface(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(COOL_Interface, self).__init__(req, link, data, **config)
        self.cool_main_program = data[simple_switch_instance_name]
        print "\n\n\n\n\n\n\n\n\nOIIIIIIIIIIIIIII"

    @route('/northbound/enable_BGP/', "/northbound/enable_BGP/", methods=['GET'])
    def enable_BGP(self, req, **kwargs):
        body = json.dumps(self.cool_main_program.domain_controller.enable_BGP_Speaker())
        return Response(content_type='application/json', body=body)

    @route('enable_BGP', "/enable_BGP/", methods=['GET'])
    def enable_BGP(self, req, **kwargs):
        body = json.dumps(self.cool_main_program.domain_controller.enable_BGP_Speaker())
        return Response(content_type='application/json', body=body)

    @route('hello_world', "/hello_world/", methods=['GET'])
    def hello_world(self, req, **kwargs):
        # print "AQUIIIIIIIIIIIIIIIIIII###################################"
        body = json.dumps(self.cool_main_program.domain_controller.hello_world())
        # "get_prefixes_learned:\n" + str(self.cool_main_program.topology_management.bgp_speaker.prefix_learned))
        return Response(content_type='application/json', body=body)


    @route('simpleswitch', url, methods=['GET'])#,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):
        #simple_switch = self.simple_switch_app
        #dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        print "Aqui!"
        print req

        print "Topo:",self.cool_main_program.mac_to_port
        result = ""
        for node in self.cool_main_program.topology:
            result +=str(node)+":"+str(self.cool_main_program.topology[node]) + "\n"
        result += "MAC: port:"+str(self.cool_main_program.mac_to_port)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    @route('create_flow', "/create_flow/", methods=['PUT'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def create_path(self, req, **kwargs):
        print req.body
        request = json.loads(req.body)
        ipv4_src = request['ipv4_src']
        ipv4_dst = request['ipv4_dst']
        primary_path = None
        if 'primary_path' in request:
            primary_path = request['primary_path']
        #print "primary_path",primary_path
        self.cool_main_program.flow_management.flow_creation(ipv4_src, ipv4_dst,primary_path=primary_path)
        print "Finished!"

    @route('get_hosts', "/get_hosts/", methods=['GET'])
    def get_hosts(self, req, **kwargs):
        # print "AQUIIIIIIIIIIIIIIIIIII###################################"
        body = json.dumps(self.cool_main_program.topology_management.hosts)
        # "get_prefixes_learned:\n" + str(self.cool_main_program.topology_management.bgp_speaker.prefix_learned))
        return Response(content_type='application/json', body=body)

    @route('get_networks', "/get_networks/", methods=['GET'])
    def get_networks(self, req, **kwargs):
        # print "AQUIIIIIIIIIIIIIIIIIII###################################"
        body = json.dumps(self.cool_main_program.topology_management.networks)
        # "get_prefixes_learned:\n" + str(self.cool_main_program.topology_management.bgp_speaker.prefix_learned))
        return Response(content_type='application/json', body=body)

    @route('get_prefixes_learned', "/get_prefixes_learned/", methods=['GET'])
    def get_prefixes_learned(self, req, **kwargs):
        # print "AQUIIIIIIIIIIIIIIIIIII###################################"
        body = json.dumps(self.cool_main_program.topology_management.bgp_speaker.prefix_learned)
        # "get_prefixes_learned:\n" + str(self.cool_main_program.topology_management.bgp_speaker.prefix_learned))
        return Response(content_type='application/json', body=body)

    @route('get_rib', "/get_rib/", methods=['GET'])
    def get_rib(self, req, **kwargs):
        #print "AQUIIIIIIIIIIIIIIIIIII###################################"
        body = json.dumps(self.cool_main_program.topology_management.bgp_speaker.get_cool_rib())
            #"get_prefixes_learned:\n" + str(self.cool_main_program.topology_management.bgp_speaker.prefix_learned))
        return Response(content_type='application/json', body=body)

    @route('get_global_flow_table', "/get_global_flow_table/", methods=['GET'])
    def get_global_flow_table(self, req, **kwargs):
        print "AQUIIIIIIIIIIIIIIIIIII\n",self.cool_main_program.flow_management.get_global_flow_table()
        body = json.dumps(self.cool_main_program.flow_management.get_global_flow_table())
        return Response(content_type='application/json', body=body)

    @route('get_flows', "/get_flows/", methods=['GET'])
    def get_flows(self, req, **kwargs):
        body = json.dumps("All paths:\n"+self.paths)
        return Response(content_type='application/json', body=body)

    @route('get_meter', "/get_meter/", methods=['GET'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_meter(self, req, **kwargs):
        self.cool_main_program.get_table_meter(1)
        print "Finished!"

    @route('simpleswitch', url, methods=['PUT'])#,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):
#        import gzip
#        with gzip.open(req, 'rb') as f:
#            file_content = f.read()
#            print type(file_content)
        simple_switch = self.cool_main_program
#        print type(req)
#       <class 'webob.request.Request'>

        #from pprint import pprint
        #pprint(req.environ)
        print req.body
        #print type(req.body_file)
        import zipfile
        if zipfile.is_zipfile(req.body_file):
            zf = zipfile.ZipFile(req.body_file)
            for info in zf.infolist():
                if info.filename == "tester.txt":
                    body = json.dumps(zf.read(info.filename))
                    return Response(content_type='application/json', body=body)
                print zf.read(info.filename)


        else:
        #dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        #try:
        #    new_entry = req.json if req.body else {}
        #except ValueError:
        #    raise Response(status=400)

        #if dpid not in simple_switch.mac_to_port:
            body = json.dumps(69)
            return Response(content_type='application/json', body=body)
            #return Response(status=404)

        try:
            mac_table = ["ERROR!"]#simple_switch.set_mac_to_port(dpid, new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)
