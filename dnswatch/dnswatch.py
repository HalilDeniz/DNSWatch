#!/usr/bin/env python3

import requests
import argparse
from scapy.all import *
from colorama import Fore, Style
from datetime import datetime, timedelta
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
from scapy.all import sniff, Ether

try:
    from .dnsdata import DNSDataStorage
except ImportError:
    from dnsdata import DNSDataStorage

dns_requests = {}
dns_types = {}

def resolve_dns_doh(dns_request):
    # DNS isteğini DoH ile çözümle
    url = f"https://cloudflare-dns.com/dns-query?name={dns_request}&type=A"
    headers = {"Accept": "application/dns-json"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            result = response.json()
            if "Answer" in result:
                answers = result["Answer"]
                return [answer["data"] for answer in answers]
        except Exception as e:
            print(f"{Fore.RED}[!] Error resolving DNS over HTTPS: {e}{Style.RESET_ALL}")

    return None
def dns_sniffer(pkt, verbose, output_file, target_ip=None, analyze_dns_types=False, use_doh=False, filter_domains=[], dns_storage=None):
    if target_ip and pkt[IP].src != target_ip and pkt[IP].dst != target_ip:
        return

    dns_storage = DNSDataStorage()

    if pkt.haslayer(DNSQR) and pkt.haslayer(Ether):
        ip_header = pkt.getlayer('IP')
        udp_header = pkt.getlayer('UDP')
        dns_request = pkt[DNSQR].qname.decode()
        dns_type = pkt[DNSQR].qtype
        dns_src_ip = pkt[IP].src
        dns_dest_ip = pkt[IP].dst
        ether_header = pkt[Ether]
        src_mac = ether_header.src
        dst_mac = ether_header.dst
        ttl = ip_header.ttl if ip_header.ttl else "N/A"
        ip_checksum = ip_header.chksum
        udp_checksum = udp_header.chksum

        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

        if filter_domains and not any(domain in dns_request for domain in filter_domains):
            return  # Skip DNS requests that don't match filter domains
        print(f"{Fore.CYAN}\tDNS Request:{Style.RESET_ALL}")
        print(f"Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
        print(f"Source IP      : {Fore.GREEN}{dns_src_ip}{Style.RESET_ALL}")
        print(f"Destination IP : {Fore.GREEN}{dns_dest_ip}{Style.RESET_ALL}")
        print(f"Source MAC     : {Style.RESET_ALL}{src_mac}")
        print(f"Destination MAC: {Style.RESET_ALL}{dst_mac}")
        print(f"Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}")
        print(f"TTL            : {Style.RESET_ALL}{ttl}")
        print(f"Type           : {Fore.GREEN}{dns_type}{Style.RESET_ALL}")
        print(f"IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}")
        print(f"UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}")
        print(f"DNS Request    : {Fore.GREEN}{dns_request}{Style.RESET_ALL}")
        print("*" * 60)

        if use_doh:
            resolved_ips = resolve_dns_doh(dns_request)
            if resolved_ips:
                print(f"{Fore.CYAN}\tDNS Request (DoH){Style.RESET_ALL}")
                print(f"Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
                print(f"Source IP      : {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL}")
                print(f"Destination IP : {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL}")
                print(f"Source MAC     : {Style.RESET_ALL}{src_mac}")
                print(f"Destination MAC: {Style.RESET_ALL}{dst_mac}")
                print(f"Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}")
                print(f"TTL            : {Style.RESET_ALL} {ttl}")
                print(f"Type           : {Fore.GREEN}{dns_type}{Style.RESET_ALL}")
                print(f"IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}")
                print(f"UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}")
                print(f"DNS Request    : {Fore.GREEN}{dns_request}{Style.RESET_ALL}")
                print(f"Resolved IPs   : {Fore.GREEN}{', '.join(resolved_ips)}{Style.RESET_ALL}")
                print("*" * 60)


            else:
                print(f"{Fore.CYAN}\tDNS Request (DoH){Style.RESET_ALL}")
                print(f"Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
                print(f"Source IP      : {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL}")
                print(f"Destination IP : {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL}")
                print(f"Source MAC     : {Style.RESET_ALL}{src_mac}")
                print(f"Destination MAC: {Style.RESET_ALL}{dst_mac}")
                print(f"Packet Size    : {len(pkt)} bytes{Style.RESET_ALL}")
                print(f"TTL            : {Style.RESET_ALL}{ttl}")
                print(f"Type           : {dns_type}")
                print(f"IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}")
                print(f"UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}")
                print(f"DNS Request    : {dns_request}")
                print(f"Resolved IPs   : (Cannot resolve with DoH)")
                print("*" * 60)

        else:
            print(f"{Fore.CYAN}\tDNS Request{Style.RESET_ALL}")
            print(f"Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
            print(f"Source IP      : {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL}")
            print(f"Destination IP : {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL}")
            print(f"Source MAC     : {Style.RESET_ALL}{src_mac}")
            print(f"Destination MAC: {Style.RESET_ALL}{dst_mac}")
            print(f"Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}")
            print(f"TTL            : {Style.RESET_ALL}{ttl}")
            print(f"Type           : {dns_type}")
            print(f"IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}")
            print(f"UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}")
            print(f"DNS Request    : {dns_request}")
            print("*" * 60)

        if dns_request in dns_requests:
            dns_requests[dns_request][0] += 1
        else:
            dns_requests[dns_request] = [1, []]

        if analyze_dns_types:
            if dns_type in dns_types:
                dns_types[dns_type] += 1
            else:
                dns_types[dns_type] = 1

        if verbose:
            print(pkt.show())

        if output_file:
            with open(output_file, "a") as file:
                file.write("\tDNS Request details:\n")
                file.write(f"Timestamp      : {timestamp}\n")
                file.write(f"Source IP      : {dns_src_ip}\n")
                file.write(f"Destination IP : {dns_dest_ip}\n")
                file.write(f"Destination IP : {dns_dest_ip}\n")
                file.write(f"Source mac     : {src_mac}\n")
                file.write(f"Packet Size    : {len(pkt)} bytes\n")
                file.write(f"Tll            : {ttl}\n")
                file.write(f"Type           : {dns_type}\n")
                file.write(f"IP Checksum    : {ip_checksum}\n")
                file.write(f"UDP Checksum   : {udp_checksum}\n")
                file.write(f"DNS Request    : {dns_request}\n")
                file.write(f"{'-' * 60}\n")
        dns_storage.insert_dns_request(timestamp, dns_src_ip, dns_dest_ip, src_mac, dst_mac, len(pkt), ttl, ip_checksum, udp_checksum, dns_request, dns_type)

    if pkt.haslayer(DNSRR):
        dns_response = pkt[DNSRR].rrname.decode()
        dns_type = pkt[DNSRR].type
        dns_src_ip = pkt[IP].src
        dns_dest_ip = pkt[IP].dst
        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

        if filter_domains and not any(domain in dns_response for domain in filter_domains):
            return  # Skip DNS responses that don't match filter domains

        print(f"{Fore.CYAN}\tDNS Response details{Style.RESET_ALL}")
        print(f"Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
        print(f"Source IP      : {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL}")
        print(f"Destination IP : {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL}")
        print(f"Source MAC     : {Style.RESET_ALL}{src_mac}")
        print(f"Destination MAC: {Style.RESET_ALL}{dst_mac}")
        print(f"Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}")
        print(f"TTL            : {Style.RESET_ALL}{ttl}")
        print(f"Type           : {dns_type}")
        print(f"IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}")
        print(f"UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}")
        print(f"DNS Response   : {dns_response}")
        print("*" * 60)

        if dns_response in dns_requests:
            dns_requests[dns_response][1].append(dns_src_ip)

        if analyze_dns_types:
            if dns_type in dns_types:
                dns_types[dns_type] += 1
            else:
                dns_types[dns_type] = 1

        if verbose:
            print(pkt.show())

        if output_file:
            with open(output_file, "a") as file:
                file.write(f"\tDNS Response details:\n")
                file.write(f"Timestamp      : {timestamp}\n")
                file.write(f"Source IP      : {dns_src_ip}\n")
                file.write(f"Destination IP : {dns_dest_ip}\n")
                file.write(f"Source mac     : {src_mac}\n")
                file.write(f"Destination Mac: {dst_mac}\n")
                file.write(f"Packet Size    : {len(pkt)} bytes\n")
                file.write(f"Tll            : {ttl}\n")
                file.write(f"Type           : {dns_type}\n")
                file.write(f"IP Checksum    : {ip_checksum}\n")
                file.write(f"UDP Checksum   : {udp_checksum}\n")
                file.write(f"DNS Response   : {dns_response}\n")
                file.write(f"{'-'*60}\n")

            dns_storage.insert_dns_request(timestamp, dns_src_ip, dns_dest_ip, src_mac, dst_mac, len(pkt), ttl, ip_checksum, udp_checksum, dns_response, dns_type)

        dns_storage.close()


def dns_data_analysis():
    if dns_requests:
        print("\nDNS Data Analysis:")
        total_requests = sum(count for count, _ in dns_requests.values())
        unique_domains = len(dns_requests)
        most_requested = max(dns_requests, key=lambda x: dns_requests[x][0])
        most_requested_count = dns_requests[most_requested][0]

        resolved_by_counts = {}
        for resolved_ips in dns_requests.values():
            for ip in resolved_ips[1]:
                if ip in resolved_by_counts:
                    resolved_by_counts[ip] += 1
                else:
                    resolved_by_counts[ip] = 1

        print(f"Total DNS Requests: {total_requests}")
        print(f"Unique Domains: {unique_domains}")
        print(f"Most Requested Domain: {most_requested} (Count: {most_requested_count})")

        print("\nMost Resolved by:")
        for ip, count in resolved_by_counts.items():
            print(f"{ip} : {count}")

        if dns_types:
            print("\nDNS Type Analysis:")
            for dns_type, count in dns_types.items():
                print(f"Type: {dns_type} - Count: {count}")
    else:
        print("No DNS requests to analyze.")


def main():
    parser = argparse.ArgumentParser(description="DNS Sniffer")
    parser.add_argument("-i", "--interface", help="Specify the network interface, for example 'eth0'", required=True)
    parser.add_argument("-v", "--verbose", help="Use this flag to get more verbose output", action="store_true")
    parser.add_argument("-o", "--output", help="Specify the filename to save the results to a file")
    parser.add_argument("-t", "--target-ip", help="Specify specific target IP address to monitor")
    parser.add_argument("-adt", "--analyze-dns-types", help="Use this flag to analyze DNS types", action="store_true")
    parser.add_argument("--doh", help="DNS over HTTPS (DoH) use this flag to use", action="store_true")
    parser.add_argument("-fd", "--target-domains", nargs="+", help="Filter DNS requests by specified domains", default=[])
    parser.add_argument("-d", "--database", help="Enable database storage", action="store_true")
    args = parser.parse_args()

    iface = args.interface
    filter_rule = "udp port 53"

    try:
        print(f"{Fore.MAGENTA}\t\tDNS Packet Sniffer started...{Style.RESET_ALL}")
        dns_storage = DNSDataStorage() if args.database else None  # Database Storage'ı isteğe bağlı olarak etkinleştirin

        sniff(iface=iface, filter=filter_rule,
              prn=lambda pkt: dns_sniffer(pkt, args.verbose, args.output, args.target_ip, args.analyze_dns_types,
                                          args.doh, args.target_domains, dns_storage))

    except PermissionError:
        print(
            f"{Fore.RED}Error: You do not have sufficient privileges. Try running the program with 'sudo'.{Style.RESET_ALL}")
        exit()
    except OSError as e:
        if "No such device" in str(e):
            print(
                f"{Fore.RED}Error: Interface '{iface}' does not exist. \nPlease provide a valid interface name.{Style.RESET_ALL}")
            exit()
        else:
            raise
    except KeyboardInterrupt:
        pass

    dns_data_analysis()


if __name__ == "__main__":
    main()

