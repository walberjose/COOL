#Manipulate IP addresses
from netaddr import *

#importando modulo do SQlite
import sqlite3

#Regular Expression
import re

import numpy

class IRR_DB():

    FILE_NAME = "database/routeviews-rv2-20180628-0000.pfx2as.small"#

    def __init__(self, file_name = "database/routeviews-rv2-20180628-0000.pfx2as.small", database_name = 'COOL_IRR_DATABASE.db', POPULATE_DATABASE=True):
        #Get database information
        self.connection = sqlite3.connect(database_name)
        self.create_ASs_table()
        self.create_Prefixes_table()
        if POPULATE_DATABASE:
            self.populate_database_from_routeview_file(file_name)
        #Test:
        #print self.seek_ASN(56203)
        # print self.seek_Prefixes('1.93.0.0/16')
        # print self.seek_Prefixes('1.0.7.0/24')
        #
        # print self.seek_ASN(4808)
        # print self.seek_ASN(23969)
        # self.seek_Prefixes('1.93.0.0/16')


    def populate_database_from_routeview_file(self,file_name):
        file = open(file_name, "r")
        num_lines = sum(1 for line in open(file_name))
        length = num_lines
        one_per = num_lines/100
        count = 0
        percent = 1
        list_of_prefixes = []
        previous_asn = -1
        for line in file:
            count+=1
            if one_per>0 and count%one_per == 0:
                print (percent,"%")
                percent+=1
            # print line
            data = line.split()
            # Prefix:
            prefix = data[0]
            # Netmask:
            netmask = data[1]
            # ASN:
            asn = data[2]

            # Insert for prefixes
            if previous_asn == -1: # Verify if its the first round ...
                previous_asn = asn
                list_of_prefixes.append(str(str(prefix) + "/" + netmask))
            else:
                #print previous_asn, asn,"!!!",previous_asn.split('_')
                if previous_asn == asn:
                    list_of_prefixes.append(str(str(prefix) + "/" + netmask))
                else:
                    for moas_asn in previous_asn.split('_'):
                        for moas_asn_final in moas_asn.split(','):
                            self.insert_entry_prefix_and_asn(moas_asn_final, list_of_prefixes)
                    list_of_prefixes = [str(str(prefix) + "/" + netmask)]

            previous_asn = asn

            # Insert for ASs
            try:
                list_of_asn = []
                for moas in asn.split('_'):
                #print "%s/%s|%s" % (prefix, netmask, moas)
                    multiple_asn = re.findall(r"[\w']+", moas)
                    #print multiple_asn,">>>>>>>>"
                    for asn in multiple_asn:
                        list_of_asn.append(int(asn))
                        #print "%s/%s|%s" % (prefix, netmask, asn)
                #if len(list_of_asn)>1:
                    #print list_of_asn,"<<<<<"
                self.insert_entry_asn_and_prefix(list_of_asn, str(prefix) + "/" + netmask)
            except:
                print ("Boiou")
        else:
            self.insert_entry_prefix_and_asn(previous_asn, list_of_prefixes)

    def seek_Prefixes(self, prefix):
        result = {}
        try:
            c = self.connection.cursor()
            c.execute("select * from Prefixes where Prefix = '" + str(prefix) + "'  ")
            for linha in c:
                asn, prefixes = linha
                list_of_prefixes = []
                # print len(prefixes.split('|')),prefixes.split('|')
                for prefix in prefixes.split('|'):
                    if len(prefix) == 0:  # Ignoring the strings '' resulted from the split
                        continue
                    list_of_prefixes.append(int(prefix))
                # print "Aquii",linha,"|",asn,prefixes
                result[asn] = list_of_prefixes
            c.close()
            #print result
            return result  # "Busca feita com sucesso!"
        except:
            return result  # "Ocorreu um erro na busca do usuario"

    def seek_ASN(self,asn):
        result = {}
        try:
            c = self.connection.cursor()
            #print "select * from ASs where ASN = '" + str(asn) + "'  "
            c.execute("select * from ASs where ASN = '" + str(asn) + "'  ")
            #c.execute("select * from ASs ")
            for linha in c:
                asn,prefixes = linha
                list_of_prefixes = []
                #print len(prefixes.split('|')),prefixes.split('|')
                for prefix in prefixes.split('|'):
                    if len(prefix) == 0: #Ignoring the strings '' resulted from the split
                        continue
                    list_of_prefixes.append(prefix)
                #print "Aquii",linha,"|",asn,prefixes
                result[asn] = list_of_prefixes
            c.close()
            #print result,"<<<"
            return result#"Busca feita com sucesso!"
        except:
            return result#"Ocorreu um erro na busca do usuario"


    '''
    Manipulation of the database:
    '''

    def create_ASs_table(self):
        c = self.connection.cursor()
        c.execute("""create table if not exists ASs (
                             ASN integer primary key autoincrement ,
                             Prefix text secondary key)""")
        self.connection.commit()
        c.close()

    def create_Prefixes_table(self):
        c = self.connection.cursor()
        c.execute("""create table if not exists Prefixes (
                             Prefix text primary key,
                             ASN text secondary key)""")
        self.connection.commit()
        c.close()

    def insert_entry_prefix_and_asn(self, asn, list_of_prefixes):
        try:
            c = self.connection.cursor()
            str_list_of_ASN = ''
            for index,prefixes in enumerate(list_of_prefixes):
                if index == len(prefixes)-1:
                    str_list_of_ASN += str(prefixes)
                else:
                    str_list_of_ASN += str(prefixes) + '|'
            #print "insert into ASs (AS_ID,prefix) values ('" + str(asn) + "', '" + str(str_list_of_ASN) + "' )"
            c.execute("insert into ASs (ASN,Prefix) values (" + asn + ", '" + str(str_list_of_ASN) + "' )")
            self.connection.commit()
            c.close()
            return "Prefix inserted into database!"
        except Exception:
            return "Prefix not inserted into database!"

    def insert_entry_asn_and_prefix(self,  list_of_ASN,prefix):
        try:
            c = self.connection.cursor()
            str_list_of_ASN = ''
            for index, asn in enumerate(list_of_ASN):
                if index == len(list_of_ASN) - 1:
                    str_list_of_ASN += str(asn)
                else:
                    str_list_of_ASN += str(asn) + '|'
            #print "insert into Prefixes (Prefix,ASN) values ('" + str(prefix) + "', '" + str(list_of_ASN) + "' )"
            c.execute("insert into Prefixes (Prefix,ASN) values ('" + str(prefix) + "', '" + str_list_of_ASN + "' )")
            #print "insert into ASs (AS_ID,prefix) values ('" + str(ASN) + "', '" + str(prefix) + "' )"
            self.connection.commit()
            c.close()
            return "AS inserted into database!"
        except Exception:
            return "AS not inserted into database!"


def split_database(file_name):
    file = open(file_name, "r")
    num_lines = sum(1 for line in open(file_name))
    list_of_files = []
    percentage = int(num_lines/10)
    for i in range(1,10+1):
        file = open(file_name, "r")
        list_of_files.append(file_name+"."+str(i))
        new_file = open(file_name + "." + str(i), "w+")
        num_of_lines_to_count = percentage*i
        count = 1
        for line in file:
            new_file.write(line)
            if count >= num_of_lines_to_count:
                print (count)
                break
            count +=1
        new_file.close()
        file.close()
    # print list_of_files
    # print num_lines



if __name__ == '__main__':
    file_name = "database/routeviews-rv2-20180628-0000.pfx2as"#"database/routeviews-rv2-20180628-0000.pfx2as.small"#"database/routeviews-rv2-20180628-0000.pfx2as"
    # Creates different file sizes based on the percentage
    #split_database(file_name)

    #Creates different data base sizes based on the percentage
    # for i in range(1,10+1):
    #     file = open(file_name + "." + str(i), "r")
    #     IRR_DB(file_name=file_name + "." + str(i),database_name='COOL_IRR_DATABASE.db'+"."+str(i))
    #     print (str(i*10)+"%")



    # prefix_src = '192.168.0.1/24'
    # ip = IPNetwork(prefix_src)
    # print ip.ip, ip.network, ip.broadcast, ip.netmask, ip.cidr

    # 1916 - RNP
    #db = IRR_DB()
    #db.seek_ASN(1916)

    connection = sqlite3.connect('COOL_IRR_DATABASE.db')
    #connection = sqlite3.connect('COOL_IRR_DATABASE.db.10')
    result = {}
    asn = 1916

    num_samples = 500
    num_of_queries = 10000

    print "#Number of queries, average, 95% confidence interval, CPU percentage, 95%, "

    import os
    import psutil

    pid = os.getpid()
    py = psutil.Process(pid)

    # memoryUse = py.memory_info()[0] / 2. ** 30  # memory use in GB...I think
    # print('memory use:', memoryUse)

    import time, psutil

    for queries in range(0,num_of_queries+1,1000):
        list_queries_time = []
        list_cpu_percentage = []
        time.sleep(1)

        try:
            c = connection.cursor()
            for i in range(0, num_samples):
                    # print "select * from ASs where ASN = '" + str(asn) + "'  "
                    start = time.time()
                    for k in range(0,queries):
                        c.execute("select * from ASs where ASN = '" + str(asn) + "'  ")
                    list_queries_time.append(time.time() - start)
                    p = psutil.Process()
                    print psutil.cpu_percent(percpu=True)
                    list_cpu_percentage.append(psutil.cpu_percent())
                    # c.execute("select * from ASs ")

            c.close()
        except:
            print result  # "Ocorreu um erro na busca do usuario"
        #95% de confianca: 1.96*
        import math
        # from scipy import stats
        # array = numpy.ndarray(list_results)
        # print stats.normaltest(array)
        print "%d,%.6f,%.6f,%.6f,%.6f"%(queries, numpy.mean(list_queries_time), 1.96 * numpy.std(list_queries_time) / math.sqrt(len(list_queries_time)),
                              numpy.mean(list_cpu_percentage), 1.96 * numpy.std(list_cpu_percentage) / math.sqrt(len(list_cpu_percentage)))#average_shortest_diamond_length), numpy.std(average_shortest_diamond_length), numpy.var(average_shortest_diamond_length)
        #0.000013,0.000006
        #0.000012,0.000003