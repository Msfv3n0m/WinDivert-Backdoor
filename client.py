from scapy.all import *
ip="127.0.0.1"
while True:
	i = input("Command: ")
	cmd = "cmd " + i
	packet = IP(dst=ip)/ICMP()/cmd
	send(packet, verbose=0)
