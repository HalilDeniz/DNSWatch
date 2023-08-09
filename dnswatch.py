import requests
import argparse
from scapy.all import *
from colorama import Fore, Style
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import IP


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
def dns_sniffer(pkt, verbose, output_file, victim_ip=None, analyze_dns_types=False, use_doh=False, filter_domains=[]):
    if victim_ip and pkt[IP].src != victim_ip and pkt[IP].dst != victim_ip:
        return

    if pkt.haslayer(DNSQR):
        dns_request = pkt[DNSQR].qname.decode()
        dns_type = pkt[DNSQR].qtype
        dns_src_ip = pkt[IP].src
        dns_dest_ip = pkt[IP].dst
        timestamp = pkt.time

        if filter_domains and not any(domain in dns_request for domain in filter_domains):
            return  # Skip DNS requests that don't match filter domains

        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} DNS Request  from {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL} to {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL} at {Fore.YELLOW}{timestamp:.6f}{Style.RESET_ALL}: {dns_request} (Type: {dns_type})")


        if use_doh:
            resolved_ips = resolve_dns_doh(dns_request)
            if resolved_ips:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} DNS Request  (DoH) from {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL} to {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL} at {Fore.YELLOW}{timestamp:.6f}{Style.RESET_ALL}: {dns_request} (Type: {dns_type}) - Resolved IPs: {', '.join(resolved_ips)}")
            else:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} DNS Request  (DoH) from {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL} to {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL} at {Fore.YELLOW}{timestamp:.6f}{Style.RESET_ALL}: {dns_request} (Type: {dns_type}) - Resolved IPs: (Cannot resolve with DoH)")
        else:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} DNS Request  from {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL} to {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL} at {Fore.YELLOW}{timestamp:.6f}{Style.RESET_ALL}: {dns_request} (Type: {dns_type})")

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
                file.write(f"DNS Request  from {dns_src_ip} to {dns_dest_ip} at {timestamp:.6f}: {dns_request} (Type: {dns_type})\n")

    if pkt.haslayer(DNSRR):
        dns_response = pkt[DNSRR].rrname.decode()
        dns_type = pkt[DNSRR].type
        dns_src_ip = pkt[IP].src
        dns_dest_ip = pkt[IP].dst
        timestamp = pkt.time

        if filter_domains and not any(domain in dns_response for domain in filter_domains):
            return  # Skip DNS responses that don't match filter domains

        print(f"{Fore.BLUE}[+]{Style.RESET_ALL} DNS Response from {Fore.CYAN}{dns_src_ip}{Style.RESET_ALL} to {Fore.CYAN}{dns_dest_ip}{Style.RESET_ALL} at {Fore.YELLOW}{timestamp:.6f}{Style.RESET_ALL}: {dns_response} (Type: {dns_type})")

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
                file.write(f"DNS Response from {dns_src_ip} to {dns_dest_ip} at {timestamp:.6f}: {dns_response} (Type: {dns_type})\n")

def dns_data_analysis():
    if dns_requests:
        print("\nDNS Data Analysis:")
        total_requests = sum(count for count, _ in dns_requests.values())
        unique_domains = len(dns_requests)
        most_requested = max(dns_requests, key=lambda x: dns_requests[x][0])
        most_requested_count = dns_requests[most_requested][0]
        most_resolved_by = ", ".join(dns_requests[most_requested][1])

        print(f"Total DNS Requests: {total_requests}")
        print(f"Unique Domains: {unique_domains}")
        print(f"Most Requested Domain: {most_requested} (Count: {most_requested_count})")
        print(f"Most Resolved by: {most_resolved_by}")

        if dns_types:
            print("\nDNS Type Analysis:")
            for dns_type, count in dns_types.items():
                print(f"Type: {dns_type} - Count: {count}")
    else:
        print("No DNS requests to analyze.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Sniffer")
    parser.add_argument("-i", "--interface", help="Specify the network interface, for example 'eth0'", required=True)
    parser.add_argument("-v", "--verbose", help="Use this flag to get more verbose output", action="store_true")
    parser.add_argument("-o", "--output", help="Specify the filename to save the results to a file")
    parser.add_argument("-k", "--victim-ip", help="Specify specific victim IP address to monitor")
    parser.add_argument("--analyze-dns-types", help="Use this flag to analyze DNS types", action="store_true")
    parser.add_argument("--doh", help="DNS over HTTPS (DoH) use this flag to use", action="store_true")
    parser.add_argument("-fd", "--filter-domains", nargs="+", help="Filter DNS requests by specified domains", default=[])
    args = parser.parse_args()

    iface = args.interface
    filter_rule = "udp port 53"

    try:
        sniff(iface=iface, filter=filter_rule,
              prn=lambda pkt: dns_sniffer(pkt, args.verbose, args.output, args.victim_ip, args.analyze_dns_types,
                                          args.doh, args.filter_domains))

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

