#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_Argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="Target_IP", help="Target IP address")
    (options, arguments) = parser.parse_args()

    if not options.Target_IP:
        parser.error("Please input ip address, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether()
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]

    client_list = []

    for element in answered_list:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def print_result(result_list):
    print("\tIP\t\t  MAC ADDRESS\n----------------------------------------------------")

    for client in result_list:
        print("  "+client["ip"]+"\t\t "+client["mac"])

options = get_Argument()
scan_result = scan(options.Target_IP)
print_result(scan_result)