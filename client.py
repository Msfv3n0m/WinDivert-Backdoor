from scapy.all import *
while True:
	i = input("Command: ")
	cmd = "cmd " + i
	packet = IP(dst="127.0.0.1")/ICMP()/cmd
	send(packet, verbose=0)
