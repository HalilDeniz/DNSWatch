import argparse
import requests
from scapy.all import *
from colorama import Fore, Style
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP, TCP
from datetime import datetime
from source.dnsfiglet import dnsfiglet
from source.dnsfirewall import DNSSpoofingDetector  # dnsfirewall dosyanızın bulunduğu yere göre import edin
from source.version import __version__

class DNSListener:
    def __init__(self, interface=None, verbose=False, target_ip=None, analyze_dns_type=False, doh=False, target_domains=None,
                 filter_port=None, filter_src_ip=None, filter_dst_ip=None, dns_type=None, pcap_file=None, firewall=False,
                 threshold=50, window_size=60):
        self.interface = interface
        self.verbose = verbose
        self.target_ip = target_ip
        self.analyze_dns_type = analyze_dns_type
        self.doh = doh
        self.target_domains = target_domains
        self.filter_port = filter_port
        self.filter_src_ip = filter_src_ip
        self.filter_dst_ip = filter_dst_ip
        self.dns_type = dns_type
        self.pcap_file = pcap_file
        self.firewall = firewall  # firewall bayrağı
        self.threshold = threshold
        self.window_size = window_size
        self.total_dns_requests = 0
        self.unique_domains = set()
        self.most_requested_domains = {}
        self.dns_types = {}
        self.source_ips = {}
        self.destination_ips = {}
        self.dns_detector = None
        self.create_dns_detector()

    def create_dns_detector(self):
        if self.firewall:
            self.dns_detector = DNSSpoofingDetector(threshold=self.threshold, window_size=self.window_size)

    def process_packet(self, pkt):
        # Ağı dinleme
        self.total_dns_requests += 1

        if DNS in pkt:
            if self.firewall and self.dns_detector:
                # Firewall modunda ise DNS spoofing tespiti yap
                self.dns_detector.process_packet(pkt)

            if self.filter_port and UDP in pkt and pkt[UDP].sport != self.filter_port and pkt[
                UDP].dport != self.filter_port:
                return

            if self.filter_src_ip and IP in pkt and pkt[IP].src != self.filter_src_ip:
                return

            if self.filter_dst_ip and IP in pkt and pkt[IP].dst != self.filter_dst_ip:
                return

            if self.dns_type and pkt[IP].proto != self.dns_type:
                return

            # Kaynak IP'yi takip et
            source_ip = pkt[IP].src
            self.source_ips[source_ip] = self.source_ips.get(source_ip, 0) + 1

            # Hedef IP'yi takip et
            destination_ip = pkt[IP].dst
            self.destination_ips[destination_ip] = self.destination_ips.get(destination_ip, 0) + 1

            if pkt.haslayer(TCP) and pkt[TCP].dport == 53:  # TCP üzerinden gelen DNS isteği
                if pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode()
                    self.unique_domains.add(qname)
                    self.most_requested_domains[qname] = self.most_requested_domains.get(qname, 0) + 1
                    if self.target_domains and qname not in self.target_domains:
                        return
                    self.print_info(pkt, "DNS Request", qname)
                    if self.doh and qname in self.target_domains:
                        self.resolve_and_print_doh_result(qname)

            elif pkt.haslayer(UDP) and pkt[UDP].dport == 53:  # UDP üzerinden gelen DNS isteği
                if pkt[DNS].qr == 0:  # DNS isteği
                    qname = pkt[DNSQR].qname.decode()
                    self.unique_domains.add(qname)
                    self.most_requested_domains[qname] = self.most_requested_domains.get(qname, 0) + 1
                    if self.target_domains and qname not in self.target_domains:
                        return
                    self.print_info(pkt, "DNS Request", qname)
                    if self.doh and qname in self.target_domains:
                        self.resolve_and_print_doh_result(qname)

                elif pkt[DNS].qr == 1:  # DNS yanıtı
                    if DNSRR in pkt:
                        qname = pkt[DNSQR].qname.decode()
                        resp_ip = pkt[DNSRR].rdata
                        if self.target_ip and resp_ip != self.target_ip:
                            return
                        self.print_info(pkt, "DNS Response", qname, resp_ip)

                        # DNS türünü takip et
                        dns_type = pkt[IP].proto
                        self.dns_types[dns_type] = self.dns_types.get(dns_type, 0) + 1

        if self.pcap_file:
            wrpcap(self.pcap_file, pkt, append=True)  # Paketleri .pcap dosyasına ekleyin.

    def resolve_and_print_doh_result(self, qname):
        resolved_ips = self.resolve_dns_doh(qname)
        if resolved_ips:
            print(f"Resolved IPs for {qname} using DoH: {resolved_ips}")

    def print_info(self, pkt, packet_type, qname, resp_ip=None, doh_result=None):
        dns_type_names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 41: "OPT", 28: "AAAA", 17: "RP"}

        dns_type = pkt[IP].proto
        dns_type_name = dns_type_names.get(dns_type, str(dns_type))

        if pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Unknown"

        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')

        print(f"{Fore.CYAN}Timestamp      :{Style.RESET_ALL}", timestamp)
        print(f"{Fore.GREEN}Source IP      :{Style.RESET_ALL}", pkt[IP].src)
        print(f"{Fore.GREEN}Destination IP :{Style.RESET_ALL}", pkt[IP].dst)
        print(f"{Fore.GREEN}Source MAC     :{Style.RESET_ALL}", pkt.src)
        print(f"{Fore.GREEN}Destination MAC:{Style.RESET_ALL}", pkt.dst)
        print(f"{Fore.GREEN}Packet Size    :{Style.RESET_ALL}", len(pkt))
        print(f"{Fore.GREEN}TTL            :{Style.RESET_ALL}", pkt.ttl)
        print(f"{Fore.GREEN}Type           :{Style.RESET_ALL}", dns_type_name)
        print(f"{Fore.GREEN}IP Checksum    :{Style.RESET_ALL}", pkt[IP].chksum)
        print(f"{Fore.GREEN}Protocol       :{Style.RESET_ALL}", protocol)
        if protocol == "UDP" and UDP in pkt:
            print(f"{Fore.GREEN}UDP Checksum   :{Style.RESET_ALL}", pkt[UDP].chksum)
        print(f"{Fore.YELLOW}{packet_type}   :{Style.RESET_ALL}", qname)
        if resp_ip:
            print(f"{Fore.YELLOW}Response IP    :{Style.RESET_ALL}", resp_ip)
        if doh_result:
            print(f"{Fore.YELLOW}DoH Result     :{Style.RESET_ALL}", doh_result)
        print("-" * 50)

    def resolve_dns_doh(self, dns_request):
        # DNS isteğini DoH ile çözümle
        url = f"https://cloudflare-dns.com/dns-query?name={dns_request}&type=A"
        headers = {"Accept": "application/dns-json"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # HTTP isteği başarısız olursa
            result = response.json()
            if "Answer" in result:
                answers = result["Answer"]
                return [answer["data"] for answer in answers]
            else:
                print(f"{Fore.RED}[!] Error: No 'Answer' field in DoH response.{Style.RESET_ALL}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Error resolving DNS over HTTPS: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
        return None

    def listen(self):
        if self.interface:
            sniff(filter="udp or tcp port 53", prn=self.process_packet, store=0, iface=self.interface)
        else:
            sniff(filter="udp or tcp port 53", prn=self.process_packet, store=0)

    def print_summary(self):
        dns_type_names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 41: "OPT", 28: "AAAA", 17: "RP"}
        print("\n")
        print(f"{Fore.BLUE}Total DNS Requests    :{Style.RESET_ALL}", self.total_dns_requests)
        print(f"{Fore.BLUE}Unique Domains        :{Style.RESET_ALL}", len(self.unique_domains))
        print(f"{Fore.BLUE}Most Requested Domains:{Style.RESET_ALL}")
        for domain, count in sorted(self.most_requested_domains.items(), key=lambda x: x[1], reverse=True):
            if count > 5:  # Eşik değeri burada 5 olarak belirledik
                print(f"\t{Fore.YELLOW}{domain}:{Style.RESET_ALL} {count} requests")
            else:
                break  # Eşik değerden az olanları görmezden gelebiliriz
        print(f"{Fore.BLUE}DNS Types:{Style.RESET_ALL}")
        for dns_type, count in sorted(self.dns_types.items()):
            dns_type_name = dns_type_names.get(dns_type, str(dns_type))
            print(f"\t{Fore.YELLOW}{dns_type_name}:{Style.RESET_ALL} {count}")

        print(f"{Fore.BLUE}Source IPs:{Style.RESET_ALL}")
        for source_ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{Fore.YELLOW}{source_ip}:{Style.RESET_ALL} {count}")

        print(f"{Fore.BLUE}Destination IPs:{Style.RESET_ALL}")
        for destination_ip, count in sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{Fore.YELLOW}{destination_ip}:{Style.RESET_ALL} {count}")


def main():
    parser = argparse.ArgumentParser(description="DNSWatch packet sniffer")
    parser.add_argument("-i", "--interface", help="Interface to listen on")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--target-ip", help="Target IP to analyze DNS responses for")
    parser.add_argument("-d", "--analyze-dns-type", action="store_true", help="Analyze DNS type")
    parser.add_argument("--doh", action="store_true", help="Resolve DNS using DNS over HTTPS (DoH)")
    parser.add_argument("-D", "--target-domains", nargs="+", default=[], help="List of target domains to monitor")
    parser.add_argument("-p", "--filter-port", type=int, help="Filter by source or destination port")
    parser.add_argument("-s", "--filter-src-ip", help="Filter by source IP address")
    parser.add_argument("-r", "--filter-dst-ip", help="Filter by destination IP address")
    parser.add_argument("--dns-type", type=int, help="Filter by DNS type")
    parser.add_argument("--pcap-file", help="Save captured packets to a pcap file")
    parser.add_argument("--firewall", action="store_true", help="Enable DNS firewall mode")
    parser.add_argument("--threshold", type=int, default=50, help="Threshold for DNS query count (default: 50)")
    parser.add_argument("--window-size", type=int, default=60, help="Window size in seconds (default: 60)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        f"\t\t{dnsfiglet()}"
        args = main()
        dns_listener = DNSListener(interface=args.interface, verbose=args.verbose, target_ip=args.target_ip,
                                   analyze_dns_type=args.analyze_dns_type, doh=args.doh, target_domains=args.target_domains,
                                   filter_port=args.filter_port, filter_src_ip=args.filter_src_ip, filter_dst_ip=args.filter_dst_ip,
                                   dns_type=args.dns_type, pcap_file=args.pcap_file,
                                   firewall=args.firewall, threshold=args.threshold, window_size=args.window_size)
        dns_listener.listen()
        dns_listener.print_summary()  # Özet raporu yazdır
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except PermissionError:
        print("Error: Permission denied. Run the program with sudo privileges.")
    except OSError as e:
        print(f"Error: Please check the interface.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
