from ryu.app.COOL.policy_management.irr_database import IRR_DB
#Manipulate IP addresses
from netaddr import *

class Policy_Management():

    # Definition of different policy types
    POLICY_DESTINATION_PREFIX_BASED = 1
    POLICY_SOURCE_ASN_BASED         = 2
    POLICY_SOURCE_PREFIX_BASED      = 3

    def __init__(self):
        #print "Enable the IRR_DB"
        self.irr_db = IRR_DB()

    '''
    The main idea is verify if the ASN_dst
    '''

    def request_flow_creation(self,policy, ASN_src, ASN_dst, ip_src, ip_dst,prefix_src=None):
        # AS_ID: all credentials need to unique identify the AS
        # Request: Includes the IP_src, IP_dst


        #If request does not contains the ASN:
            #Fetch the ASN using the IP_src

        #Policy: Destination prefix based
        if policy == self.POLICY_DESTINATION_PREFIX_BASED:
            self.destination_prefix_based(ASN_src=None, ASN_dst=ASN_dst, ip_src=None, ip_dst=ip_dst)
        elif policy == self.POLICY_SOURCE_ASN_BASED:
            self.source_ASN_based(ASN_src=ASN_src, ASN_dst=ASN_dst, ip_src=ip_src, ip_dst=ip_dst)
        elif policy == self.POLICY_SOURCE_PREFIX_BASED:
            self.source_prefix_based( ip_src=ip_src,prefix_src=prefix_src,ASN_src=ASN_src)

    '''
    Policy: Destination prefix based
    '''

    def destination_prefix_based(self, ASN_src, ASN_dst, ip_src, ip_dst):
        if self.verify_ip_belongs_to_asn(ip_dst, ASN_dst):
            return True
        else:
            return False

    '''
    Policy: Source ASN based
    '''
    def source_ASN_based(self,ASN_src, ASN_dst, ip_src, ip_dst):
        if self.verify_ip_belongs_to_asn(ip_dst, ASN_dst) and self.verify_ip_belongs_to_asn(ip_src, ASN_src):
            return True
        else:
            return False


    '''
    Policy: Source prefix based
    '''
    def source_prefix_based(self,ip_src,prefix_src,ASN_src):
        import SubnetTree
        t = SubnetTree.SubnetTree()
        t[str(prefix_src)] = ""
        if (ip_src in t):
            return True
        else:
            return False


    def verify_ip_belongs_to_asn(self, ip_dst, asn):
        prefixes_of_asn = self.irr_db.seek_ASN(asn)
        #print prefixes_of_asn
        for asn in prefixes_of_asn:
            for prefix in prefixes_of_asn[asn]:
                #print prefix,type(prefix),prefixes_of_asn,ip_dst,"<<"
                import SubnetTree
                t = SubnetTree.SubnetTree()
                t[str(prefix)] = "Network 1, Subnet 42"
                #print ('10.0.0.2' in t)
                #if IPNetwork(prefix) == IPNetwork(ip_dst):
                if (ip_dst in t):
                    print ip_dst,prefix,"<<<",prefixes_of_asn[asn]
                    return True
        return False

    def verify_destination_prefix_based_policy(self, ip_dst, asn):
        return self.verify_ip_belongs_to_asn( ip_dst, asn)

    '''{*, ASN_{src}, *, ASN_{dst} }'''
    def verify_source_asn_based_policy(self,ip_src,asn_src, ip_dst, asn_dst):
        return self.verify_ip_belongs_to_asn(ip_src,asn_src) and self.verify_ip_belongs_to_asn(ip_dst,asn_dst)



if __name__ == '__main__':

    #(Prefix_{src}, ASN_{src}, Prefix_{dst}, ASN_{dst})
    #policy_object = {'prefix_src':'10.0.0.1', 'asn_src':12, 'prefix_dst':'10.0.0.2', 'asn_dst':2}

    #getting_BGP_update()
    #MOAS_prefixes()
    # prefix_src = '192.168.0.1/24'
    # ip = IPNetwork(prefix_src)
    # print ip.ip, ip.network, ip.broadcast, ip.netmask, ip.cidr

    policy_mangement = Policy_Management()
    #print policy_mangement.verify_ip_belongs_to_asn(asn=17429, ip_dst='1.91.0.0/17')
    request_false = ('10.0.0.1','192.168.0.1')
    request_true = ('10.0.0.1','1.91.128.1')

    ASN = 17429
    policy_mangement.request_flow_creation(ASN_dst=ASN, request=request_true)

    #print IPNetwork('1.91.128.1') == IPNetwork('1.91.0.0/17')
    # ip = IPNetwork('1.91.128.1').cidr
    # print ip
    # print IPNetwork('1.91.128.1').network
    # print IPNetwork('1.91.0.0/17').network

    import SubnetTree
    t = SubnetTree.SubnetTree()
    t[str('1.91.0.0/17')] = "Network 1, Subnet 42"
    #print ('10.0.0.2' in t)
    #if IPNetwork(prefix) == IPNetwork(ip_dst):
    if ('1.91.128.1' in t):
        print True
    else:
        print False