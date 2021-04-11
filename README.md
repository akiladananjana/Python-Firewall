# Python-Firewall
Python based Packet Filtering Firewall

# What is Packet Filtering Firewall?
Packet filtering firewall is a network security technique that is used to control data flow to and from a network. It is a security mechanism that allows the movement of packets across the network and controls their flow on the basis of a set of rules, protocols, IP addresses, and ports.

# How this Firewall works?
In this simple firewall, I added 4 interfaces and these interfaces are running on threads for receive the traffic simultaneously. All the traffic forward into one funtion and It checks the packets against the set of rules defines in text file. If there no rule matches, the traffic allowed and forwarded to its destination.

# Top Features
* Four interfaces for filtering
* Port level and IP level blocking
