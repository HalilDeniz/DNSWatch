from colorama import Fore, Style
from scapy.all import sniff, DNS, IP
from collections import defaultdict
from datetime import datetime, timedelta

class DNSSpoofingDetector:
    def __init__(self, threshold=50, window_size=60):
        self.threshold = threshold  # Zaman dilimi içindeki maksimum DNS sorgu sayısı
        self.window_size = window_size  # Zaman dilimi (saniye cinsinden)
        self.dns_queries = defaultdict(list)

    def process_packet(self, pkt):
        if DNS in pkt:
            query_time = datetime.now()
            src_ip = pkt[IP].src
            dns_id = pkt[DNS].id

            # Önceki sorguları temizle
            self.clean_old_queries(query_time)

            # Bu sorguyu listeye ekle
            self.dns_queries[src_ip].append((dns_id, query_time))

            # Belirli bir zaman dilimi boyunca sorgu sayısını kontrol et
            if len(self.dns_queries[src_ip]) > self.threshold:
                print(f"{Fore.RED}[!] Possible DNS spoofing detected from {src_ip}!")
                print(f"{Fore.BLUE}\tNumber of DNS queries within the last {self.window_size} seconds: {len(self.dns_queries[src_ip])}")
                print(f"{Fore.BLUE}\tRecent DNS query IDs: {', '.join(str(query[0]) for query in self.dns_queries[src_ip][-5:])}")
                print(f"{Fore.BLUE}\tTimestamp of the last query: {self.dns_queries[src_ip][-1][1]}")
                print(Style.RESET_ALL)

    def clean_old_queries(self, current_time):
        # Zaman dilimi dışındaki sorguları temizle
        for ip, queries in self.dns_queries.items():
            self.dns_queries[ip] = [(dns_id, query_time) for dns_id, query_time in queries
                                     if query_time >= current_time - timedelta(seconds=self.window_size)]

    def set_threshold(self, threshold):
        self.threshold = threshold

    def set_window_size(self, window_size):
        self.window_size = window_size