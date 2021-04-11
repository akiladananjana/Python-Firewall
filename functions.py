from ipaddress import ip_network, ip_address #check if an IP is within a range of CIDR
import netifaces #Module to retrive connected ethernet interface details
from ipaddress import IPv4Network #To Get CIDR Number
import ipaddress
import struct
import sys


#This function retrives the connected interface details
def get_connected_interface_details():

    #Get names of the all interfaces(names only)
    interfaces_name_list = (netifaces.interfaces())[1:]
    int_ip_mask = [] #To store temp veriables. This sub-list attach to main interface list.(interfaces_list)
    interfaces_list = [] #this list used to store all interfaces details as sub-lists [[int1_details_dict],[int2_details_dict]]

    for _int_ in interfaces_name_list:

        #netifaces.ifaddresses(interface_name) return details about the specified interface
        all_interface_details = netifaces.ifaddresses(_int_)

        #Output error msg if interface has no IP address
        try:
            #all_interface_details[netifaces.AF_INET] returns interface ip address eg=> [{'addr': '192.168.2.1', 'netmask': '255.255.255.0', 'broadcast': '192.168.2.255'}]
            int_ip_mask = all_interface_details[netifaces.AF_INET]
        except KeyError as no_ip_details_error:
            print("\nError! Please Configure IP Details for all the interfaces\n")
            sys.exit()

        #Add interface name into list
        int_ip_mask[0]['int_name'] = _int_

        #Add CIDR Number into list
        int_ip_mask[0]['cidr'] = IPv4Network('0.0.0.0/' + (int_ip_mask[0]['netmask'])).prefixlen 

        #Add network ID into list
        int_ip_mask[0]['network_id'] = str(((ipaddress.IPv4Network( (int_ip_mask[0]['addr']) + '/' + (int_ip_mask[0]['netmask']), strict=False))).network_address) 

        #Append all interfaces into single list
        interfaces_list.append(int_ip_mask)

    return (interfaces_list)


