import sqlite3

class DNSDataStorage:
    def __init__(self, db_file="dnsdata.db"):
        self.db_file = db_file
        self.connection = self.create_connection()
        if self.connection:
            self.create_table()

    def create_connection(self):
        try:
            return sqlite3.connect(self.db_file)
        except sqlite3.Error as e:
            print("Failed to connect to the database:", e)
            return None

    def create_table(self):
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_mac TEXT,
                    destination_mac TEXT,
                    packet_size INTEGER,
                    ttl TEXT,
                    ip_checksum INTEGER,
                    udp_checksum INTEGER,
                    domain TEXT,
                    dns_type INTEGER
                )
            ''')
            self.connection.commit()
        except sqlite3.Error as e:
            print("Database error:", e)

    def insert_dns_request(self, timestamp, source_ip, destination_ip, source_mac, destination_mac, packet_size, ttl, ip_checksum, udp_checksum, domain, dns_type):
        if not self.connection:
            print("No database connection")
            return
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO dns_requests (timestamp, source_ip, destination_ip, source_mac, destination_mac, packet_size, ttl, ip_checksum, udp_checksum, domain, dns_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, source_ip, destination_ip, source_mac, destination_mac, packet_size, ttl, ip_checksum, udp_checksum, domain, dns_type))
            self.connection.commit()
        except sqlite3.Error as e:
            print("Database error:", e)

    def retrieve_dns_requests(self):
        if not self.connection:
            print("No database connection")
            return []
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM dns_requests")
            return cursor.fetchall()
        except sqlite3.Error as e:
            print("Database error:", e)
            return []

    def close(self):
        if self.connection:
            self.connection.close()
