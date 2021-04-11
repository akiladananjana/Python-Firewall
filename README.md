# Python-Firewall
Python based Packet Filtering Firewall

# What is Packet Filtering Firewall?
Packet filtering firewall is a network security technique that is used to control data flow to and from a network. It is a security mechanism that allows the movement of packets across the network and controls their flow on the basis of a set of rules, protocols, IP addresses, and ports.

# How this Firewall works?
In this simple firewall, I added 4 interfaces and these interfaces are running on threads for receive the traffic simultaneously. All the traffic forward into one funtion and It checks the packets against the set of rules defines in text file. If there no rule matches, the traffic allowed and forwarded to its destination.

# Top Features
* Four interfaces for filtering
* Port level and IP level blocking

## Define Firewall Rules in confing.ini as follows

====By default all the traffic allowed!====

Empty the file for allow all the traffic </br>

### Rule Syntax <br/>  
DENY <SRC_IP> <SRC_PORT> <DST_IP> <DST_PORT> 


Eg:-

192.168.1.10 20 192.168.1.20 50 <br/> 
Block any packet with Source 192.168.1.10:20 to Dest 192.168.1.20:50


DENY ANY ANY 192.168.1.10 80 <br/> 
Block packet from any source that destinationed to ip 192.168.1.20 and port 80


## Requirements to run this Firewall
* Four Interfaces with Static IP configured
* All the interfaces should be active
* Python 3.8.2 (tested)
* Ubuntu 20.04 box (tested)

## How to fire this firewall?

* Enter into python virtual environment </br>
``` source env1/bin/activate ```

* Execute </br>
``` python3 firewall.py ```
