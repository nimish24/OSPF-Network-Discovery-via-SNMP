#!/usr/bin/env python
#Nimish Kulkarni
# Application 5.....OSPF SNMP

import pprint
import subprocess
import sys
import binascii

try:
    import matplotlib.pyplot as matp
except ImportError:
    print Fore.RED + Style.BRIGHT + "\n* Module matplotlib needs to be installed on your system."
    print "*Download it from: https://pypi.python.org/pypi/metaplotlib\n" + Fore.WHITE + Style.BRIGHT
    sys.exit()
    
try:
    import networkx as nx
except ImportError:
    print Fore.RED + Style.BRIGHT + "\n* Module networkx needs to be installed on your system."
    print "*Download it from: https://pypi.python.org/pypi/decorator\n" + Fore.WHITE + Style.BRIGHT
    sys.exit()
    
try:
    from colorama import init,deinit,Fore,Style
except ImportError:
    print Fore.RED + Style.BRIGHT + "\n* Module colorama needs to be installed on your system."
    print "*Download it from: https://pypi.python.org/pypi/colorama\n" + Fore.WHITE + Style.BRIGHT
    sys.exit()
    
try:    
    
    from pysnmp.entity.rfc3413.oneliner import cmdgen
    
except:
    print Fore.RED + Style.BRIGHT + "\n* Module pysnmp needs to be installed on your system."
    print "*Download it from: https://pypi.python.org/pypi/pysnmp\n" + Fore.WHITE + Style.BRIGHT
    sys.exit()
    
#input the ip address and community string

try:
    print Style.BRIGHT + "\n####################### OSPF DISCOVERY TOOL ####################\n"
    print "Make sure to connect to device running OSPF in the network\n"
    print "SNMP community string should be same on all devices in the network\n"
    ip = raw_input(Fore.GREEN + "\nPlease enter root device IP: ")
    comm = raw_input("\nPlease enter the community string: ")
except KeyboardInterrupt:
    print Fore.RED + Style.BRIGHT + "\nProgram aborted by the user.Exiting...\n"
    sys.exit()
    
    
def ip_is_valid():
    while True:
        a = ip.split('.')
        
        if(len(a)==4) and(1<=int(a[0])<=223) and  (int(a[0]) != 127) and (int(a[0]) != 169 or int(a[1]) != 254) and ( 0<= int(a[0]) <= 255 and 0 <= int(a[1]) <=255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255):
            break
        else:
            print Fore.RED + Style.BRIGHT + "\nIP address is invalid. Please check again."
            sys.exit()            
    
    #Checking IP reachability
    
    print Fore.GREEN + Style.BRIGHT + "\nChecking IP reachability...\n"
    
    while True:
        ping_reply = subprocess.call(['ping','-c','3','-w','3','-q','-n',ip],stdout = subprocess.PIPE)
        
        if ping_reply == 0:
            print Fore.GREEN + Style.BRIGHT + "\nThe device is reachable. Performing SNMP extraction...\n"
            print "This may take a few moments.....\n"
            break
        
        elif ping_reply == 2:
            print Fore.RED + Style.BRIGHT + "\nThe device  %s is not reachable.\n" %ip
            print "Please check the connection and try again...\n"
            sys.exit()
            
        else:
            print Fore.RED + "\nPing to device %s has failed. Please check the connection and try again later" %s
            sys.exit()

try:
    ip_is_valid()
    
except KeyboardInterrupt:
    print Fore.RED + Style.BRIGHT + "\nProgram aborted by the user. Exiting.....\n"
    sys.exit()
            
ospf = []

def snmp_get(ip):
    nbridlist = []
    nbriplist = []
    ospf_devices = {}
    
    #Creating command generator object
    cmdGen = cmdgen.CommandGenerator()
    
    #Performing SNMP GETNEXT operations on OSPF OIDS
    #Basic syntax of nextCmd method: nextCmd(authData, transportTarget, *varNames)
    #nextCmd returns a tuple of (errorIndication, errorStatus, errorIndex, varBindTable)
    
    errorIndication, errorStatus, errorIndex, varBindNbrTable = cmdGen.nextCmd(cmdgen.CommunityData(comm),
                                                                               cmdgen.UdpTransportTarget((ip,161)),
                                                                                '1.3.6.1.2.1.14.10.1.3')
    
    errorIndication, errorStatus, errorIndex, varBindNbrIpTable = cmdGen.nextCmd(cmdgen.CommunityData(comm),
                                                                               cmdgen.UdpTransportTarget((ip,161)),
                                                                                '1.3.6.1.2.1.14.10.1.1')
    
    errorIndication, errorStatus, errorIndex, varBindHostTable = cmdGen.nextCmd(cmdgen.CommunityData(comm),
                                                                               cmdgen.UdpTransportTarget((ip,161)),
                                                                                '1.3.6.1.4.1.9.2.1.3')
    
    errorIndication, errorStatus, errorIndex, varBindHostIdTable = cmdGen.nextCmd(cmdgen.CommunityData(comm),
                                                                               cmdgen.UdpTransportTarget((ip,161)),
                                                                                '1.3.6.1.2.1.14.1.1')
    
    
    
    #Extract and print out the results
    for varBindNbrTableRow in varBindNbrTable:
        for oid, nbrid in varBindNbrTableRow:
            hex_string = binascii.hexlify(str(nbrid))
            #print hex_string
            octets = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
            #print octets
            ip = [int(i, 16) for i in octets]
            #print ip
            nbr_r_id = '.'.join(str(i) for i in ip)
            #print nbr_r_id
            nbridlist.append(nbr_r_id)
            
    for varBindNbrIpTableRow in varBindNbrIpTable:
        for oid, nbrip in varBindNbrIpTableRow:
            hex_string = binascii.hexlify(str(nbrip))
            #print hex_string
            octets = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
            #print octets
            ip = [int(i, 16) for i in octets ]
            #print ip
            nbr_r_ip = '.'.join(str(i) for i in ip)
            #print nbr_r_ip
            nbriplist.append(nbr_r_ip)
            
    for varBindNbrHostTableRow in varBindHostTable:
        for oid, host in varBindNbrHostTableRow:
            ospf_host = str(host)
            
    for varBindHostIdTableRow in varBindHostIdTable:
        for oid, host_id in varBindHostIdTableRow:
            hex_string = binascii.hexlify(str(host_id))
            octets = [hex_string[i:i+2] for i in range(0, len(hex_string),2) ]
            ip = [int(i, 16) for i in octets]
            ospf_host_id = '.'.join(str(i) for i in ip)
            
    #insert data into ospf_devices dictionary
    
    ospf_devices["host"] = ospf_host
    ospf_devices["Host ID"] = ospf_host_id
    ospf_devices["NbrRtsId"] = nbridlist
    ospf_devices["NbrRtsIp"] = nbriplist
    
    ospf.append(ospf_devices)
    return ospf
    
ospf = snmp_get(ip)
#pprint.pprint(ospf)

def find_unqueried_neighbors():
    all_host_ids = []
    
    for n in range(0,len(ospf)):
        hid = ospf[n]["Host ID"]
        all_host_ids.append(hid)
        
    #print "HID"
    #print all_host_ids
    #print "\n"
    
    all_nbr_ids = []
    
    for n in range(0,len(ospf)):
        for each_id in ospf[n]["NbrRtsId"]:
            if each_id == "0.0.0.0":
                pass
            else:
                all_nbr_ids.append(each_id)
    
    #print "NBR"            
    #print all_nbr_ids
    #print "\n"
    
    all_outsiders = []
    
    for p in all_nbr_ids:
        if p not in all_host_ids:
            all_outsiders.append(p)
            
    #print "OUT"
    #print all_outsiders
    #print "\n"
    
    #Running snmp_get() on all unqueried neighbors
    
    for q in all_outsiders:
        for r in range(0, len(ospf)):
            for index, s in enumerate(ospf[r]["NbrRtsId"]):
                
                if q == s:
                    new_ip = ospf[r]["NbrRtsIp"][index]
                    snmp_get(new_ip)
                else:
                    pass
                
    return all_host_ids, all_nbr_ids, ospf

#calling the above function
while True:
    if (len(list(set(find_unqueried_neighbors()[0]))) == len(list(set(find_unqueried_neighbors()[1])))):
        break
    
final_devices_list = find_unqueried_neighbors()[2]

#pprint.pprint(final_devices_list)                    
 
neighborship_dict = {}

for  each_dictionary in final_devices_list:
    for index, each_neighbor in enumerate(each_dictionary["NbrRtsId"]):
        
        each_tuple = (each_dictionary["Host ID"], each_neighbor)
        neighborship_dict[each_tuple] = each_dictionary["NbrRtsIp"][index]
#pprint.pprint(neighborship_dict)


############## PART 5 ##############
while True:
    try:
        print Fore.BLUE + Style.BRIGHT + "\nPlease choose an option:\n\n1 - Display all OSPF devices on the screen\n2 - Export OSPF devices to CSV file\n3 - Generate OSPF topology\ne - Exit"
        user_choice = raw_input("\nEnter your choice: ")
        print "\n"
        
        if  user_choice == "1":
            for each_dict in final_devices_list:
                print "Hostname: " + Fore.YELLOW + Style.BRIGHT + "%s" % each_dict["host"] + Fore.BLUE + Style.BRIGHT
                print "Host ID: " + Fore.YELLOW + Style.BRIGHT + "%s" %each_dict["Host ID"] + Fore.BLUE + Style.BRIGHT
                print "OSPF  neighbour ID: " + Fore.YELLOW + Style.BRIGHT + "%s" % ', '.join(each_dict["NbrRtsId"]) + Fore.BLUE + Style.BRIGHT
                print "OSPF neighbor IP: " + Fore.YELLOW + Style.BRIGHT + "%s" % ', '.join(each_dict["NbrRtsIp"]) + Fore.BLUE + Style.BRIGHT
                print "\n"
            continue
        
        elif user_choice == "2":
            print Fore.CYAN + Style.BRIGHT + "Generating " +Fore.YELLOW + Style.BRIGHT + "OSPF_DEVICES " + Fore.CYAN + Style.BRIGHT + "file....\n"
            print Fore.CYAN + Style.BRIGHT + "Check the script folder. Import the file in excel for better view of the devices\n"
            csv_file = open("OSPF_DEVICES.txt","w")
            
            print >>csv_file, "Hostname" + ";" + "OSPFRouterID" + ";" + "OSPFNeighborRouterID" + ";" + "OSPFNeibhborRouterIP"
            
            for each_dict in final_devices_list:
                print >>csv_file, each_dict["host"] + ";" + each_dict["Host ID"] + ";" + ', '.join(each_dict["NbrRtsId"]) + ";" + ', '.join( each_dict["NbrRtsIp"])
                
            csv_file.close()
            
            continue
        
        ################### Generating OSPF Network topology ############
                
        elif user_choice == "3":
            print Fore.CYAN + Style.BRIGHT + "\nGenerating OSPF network topology....\n" + Fore.BLUE + Style.BRIGHT
            
            G = nx.Graph()
            G.add_edges_from(neighborship_dict.keys())
            pos = nx.spring_layout(G, k=0.1, iterations = 70)
            nx.draw_networkx_labels(G, pos, font_size = 9, font_family = "sans-serif", font_weight = "bold" )
            nx.draw_networkx_edges(G, pos, width = 4, alpha = 0.4, edge_color = 'black')
            nx.draw_networkx_edge_labels(G, pos, neighborship_dict, label_pos = 0.3, font_size = 6)
            nx.draw(G, pos, node_size = 700, with_labels = False)
            matp.show()
            continue
        
        elif user_choice == "e":
            print Fore.CYAN + Style.BRIGHT + "Exiting the program. Bye....\n" + Fore.WHITE + Style.BRIGHT
            sys.exit()
        
        else:
            print Fore.RED + Style.BRIGHT + "\nInvalid option\n"
            continue
        
    except KeyboardInterrupt:
        print Fore.RED + Style.BRIGHT + "\nProgram aborted by the user. Exiting.....\n"
        sys.exit()
        
deinit()
        
        

