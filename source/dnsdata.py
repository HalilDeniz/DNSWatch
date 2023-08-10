import sqlite3

class DNSDataStorage:
    def __init__(self, db_file="dns_data.db"):
        self.db_file = db_file
        self.connection = None
        self.create_table()

    def create_table(self):
        try:
            self.connection = sqlite3.connect(self.db_file)
            cursor = self.connection.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    domain TEXT,
                    dns_type INTEGER
                )
            ''')
            self.connection.commit()
        except sqlite3.Error as e:
            print("Database error:", e)

    def insert_dns_request(self, timestamp, source_ip, destination_ip, domain, dns_type):
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO dns_requests (timestamp, source_ip, destination_ip, domain, dns_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, source_ip, destination_ip, domain, dns_type))
            self.connection.commit()
        except sqlite3.Error as e:
            print("Database error:", e)

    def close(self):
        if self.connection:
            self.connection.close()
