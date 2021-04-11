import time
import functions
import sys
import threading
import unpack_headers
import socket

#============================================================================================================================
#Load Firewall Configurations

rule_set=[]
with open("config.ini", 'r') as file_handler:
    data = file_handler.readline()
    #Insert all the firewall rules into 'rule_set' verialble
    while(data):
        rule_set.append(data.rstrip('\n').split(" "))
        data = file_handler.readline()

def check_firewall_rule(src_ip, src_port, dst_ip, dst_port)->bool:
    #Check rules in 'rule_set' with Receved Packet's IP, Port
    for rule in rule_set:
        
        if((src_ip == rule[1] or rule[1]=='ANY' ) and (src_port == rule[2] or rule[2] == 'ANY') and (dst_ip == rule[3] or rule[3] == 'ANY' ) and (dst_port ==  rule[4] or rule[4] == 'ANY') ):
            
            #If there any matches, then return False to ignore the packet
            return False
            break

    #If there NO any matches, then return True to forward the packet
    return True

#============================================================================================================================

#Get details about all the connected interfaces
interfaces_list = functions.get_connected_interface_details()

# Above function returns list like this => [[{'addr': '192.168.1.10', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255', 'int_name': 'ens33', 'cidr': 24, 'network_id': '192.168.1.0'}], [{'addr': '172.16.1.1', 'netmask': '255.255.255.0', 'broadcast': '172.16.1.255', 'int_name': 'ens38', 'cidr': 24, 'network_id': '172.16.1.0'}], [{'addr': '10.0.0.1', 'netmask': '255.255.255.0', 'broadcast': '10.0.0.255', 'int_name': 'ens39', 'cidr': 24, 'network_id': '10.0.0.0'}], [{'addr': '192.168.2.1', 'netmask': '255.255.255.0', 'broadcast': '192.168.2.255', 'int_name': 'ens40', 'cidr': 24, 'network_id': '192.168.2.0'}]]

#============================================================================================================================

#Create Send Socket for all the interfaces
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
send_sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

#Create a Recv Sockets for all the interfaces
sock1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
sock1.bind((interfaces_list[0][0]['int_name'], 0))

sock2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
sock2.bind((interfaces_list[1][0]['int_name'], 0))

sock3 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
sock3.bind((interfaces_list[2][0]['int_name'], 0))

sock4 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
sock4.bind((interfaces_list[3][0]['int_name'], 0))



#Define each Interface in a separate function for forward all the traffic to send_ip_packet() function.
def interface1(int_name):
    while True:
        ip_frame = sock1.recvfrom(65535)[0]
        send_ip_packet(ip_frame, int_name, sock1)

def interface2(int_name):
    while True:
        ip_frame = sock2.recvfrom(65535)[0]
        send_ip_packet(ip_frame, int_name, sock2)

def interface3(int_name):
    while True:
        ip_frame = sock3.recvfrom(65535)[0]
        send_ip_packet(ip_frame, int_name, sock3)
        

def interface4(int_name):
    while True:
        ip_frame = sock4.recvfrom(65535)[0]
        send_ip_packet(ip_frame, int_name, sock4)


int1_thread = threading.Thread(target=interface1, args=(interfaces_list[0][0]['int_name'], ) )
int2_thread = threading.Thread(target=interface2, args=(interfaces_list[1][0]['int_name'], ) )
int3_thread = threading.Thread(target=interface3, args=(interfaces_list[2][0]['int_name'], ) )
int4_thread = threading.Thread(target=interface4, args=(interfaces_list[3][0]['int_name'], ) )


#Start all threads as daemon mode, then we can close them all when the main program ends! 
#To keep alive main program add a infinite while loop at begining of the program.Catch keyboard interrupt using that loop. 
int1_thread.setDaemon(True)
int1_thread.start()
int2_thread.setDaemon(True)
int2_thread.start()
int3_thread.setDaemon(True)
int3_thread.start()
int4_thread.setDaemon(True)
int4_thread.start()


#This function gets all the traffic from different interfaces & check with firewall rules.
def send_ip_packet(frame, int_name, socket_handler):
    #Extract the IP dst & src addresses
    
    ip_packet = unpack_headers.IP_Header(frame[14:34])
    dst_ip = ip_packet.dst_address
    src_ip = ip_packet.src_address


    #Check the upper layer protocol(4th Layer)
    transport_proto = ip_packet.trns_proto

    #Initilize the veriables for src and dst port numbers
    src_port = "x"
    dst_port = "x"

    if(transport_proto == 6):
        #Extract the TCP dst & src Ports
        tcp_packet = unpack_headers.TCP_Header(frame[34:54])
        src_port = int(tcp_packet.src_port, 16) #Convert hex string to decimal
        dst_port = int(tcp_packet.dst_port, 16) #Convert hex string to decimal

    elif(transport_proto == 17):
        #Extract the UDP dst & src Ports
        udp_packet = unpack_headers.UDP_Header(frame[34:42])
        src_port = int(udp_packet.src_port, 16) #Convert hex string to decimal
        dst_port = int(udp_packet.dst_port, 16) #Convert hex string to decimal

    
    #If there no firewall rule, then check_firewall_rule() function return True
    if( check_firewall_rule(src_ip, str(src_port), dst_ip, str(dst_port)) ):
        try:
            send_sock.sendto(frame[14:], (dst_ip , 0))
        except PermissionError as broadcastError:
            pass
        except OSError as Error :
            pass
        


#============================================================================================================================
#To keep alive the main thread and catch the KeyboardInterrupt exception

def generate_slash_ani():
    print("\nFirewall is running ", end="")
    while (True):
        for x in "|/—\\":
            sys.stdout.write(x)
            sys.stdout.flush()
            time.sleep(0.2)
            sys.stdout.write('\b')

try:
    generate_slash_ani()
        
except KeyboardInterrupt as key_intrrupt:
    sys.exit()
