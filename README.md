# lupin
Empire: LupinOne is a Vulnhub easy-medium machine designed by icex64 and Empire
Cybersecurity.
Pentesting Methodology
Network Scanning
● netdiscover
● nmap
Enumeration
● abusing HTTP
● fuzzing
Exploitation
● john
● ssh
Privilege Escalation
● linpeas
● python library hijacking
● pip
● root flag
Level: Easy-Medium
Network Scanning
To begin, we must use the netdiscover command to scan the network for the IP address of the
victim machine.
To move forward in this process, we are launching Nmap.
nmap -sC -sV 192.168.1
We have, according to the nmap output:
● on port 22 there is an SSH server.
● an HTTP service (Apache Server) running on port 80, as well as a /~myfiles
