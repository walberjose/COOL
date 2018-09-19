

class Neighbor():
    # self.neighbor = {"10.0.1.1": {'asn': 65001, 'switch': 2, 'port': 1, 'controller_ip': "10.0.1.254"},
    #                  "10.0.2.2": {'asn': 65002, 'switch': 2, 'port': 2, 'controller_ip': "10.0.2.254"},
    #                  }
    def __init__(self,ip,asn,next_hop,border_switch,sw_port,controller_ip):
        self.ip = ip
        self.asn = asn
        self.next_hop = next_hop
        self.border_switch = border_switch
        self.sw_port = sw_port
        self.controller_ip = controller_ip

    def get_IP(self):
        return self.ip

    def get_ASN(self):
        return self.asn

    def get_next_hop(self):
        return self.next_hop

    def get_border_switch(self):
        return self.border_switch
