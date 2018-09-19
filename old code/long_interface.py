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

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/'

class Long_Interface(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(Long_Interface, self).__init__(req, link, data, **config)
        self.cool = data[simple_switch_instance_name]

    @route('simpleswitch', url, methods=['GET'])#,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):
        #simple_switch = self.simple_switch_app
        #dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        print "Aqui!"
        print req

        print "Topo:",self.cool.mac_to_port
        result = ""
        for node in self.cool.topology:
            result +=str(node)+":"+str(self.cool.topology[node]) + "\n"
        result += "MAC: port:"+str(self.cool.mac_to_port)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    @route('create_path', "/create_path/", methods=['PUT'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def create_path(self, req, **kwargs):
        self.cool.creating_paths()
        print "Finished!"

    # OK!
    @route('get_installed_instructions', "/get_installed_instructions/", methods=['GET'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_installed_instructions(self, req, **kwargs):
        body = json.dumps(str(self.cool.get_installed_instructions()))
        return Response(content_type='application/json', body=body)

    #OK!
    @route('get_bandwidth', "/get_bandwidth/", methods=['GET'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_bandwidth(self, req, **kwargs):
        body = json.dumps(str(self.cool.get_bandwidth_utilization()))
        return Response(content_type='application/json', body=body)

    #OK!
    @route('get_prefixes', "/get_prefixes/", methods=['GET'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_prefixes(self, req, **kwargs):
        list_of_prefixes = '{"prefix":{"value":"192.168.0.0","netmask":24,"paths": [{"path":[1,2,3],"available_bandwidth":100,"current_bandwidth":30},{"path":[1,4,3],"available_bandwidth":100,"current_bandwidth":65}]}}'
        body = json.dumps(str(list_of_prefixes))
        return Response(content_type='application/json', body=body)

    #POST is used for send a form, for example.
    @route('loadbalacing', "/loadbalacing/", methods=['POST'])  # ,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def set_load_balancing(self, req, **kwargs):
        #Receiving the weights of the load balacing!!!
        body = json.dumps('Ok!'+str(req))
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', url, methods=['PUT'])#,requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):
#        import gzip
#        with gzip.open(req, 'rb') as f:
#            file_content = f.read()
#            print type(file_content)
        simple_switch = self.cool
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