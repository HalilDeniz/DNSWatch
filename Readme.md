# DNSWatch - DNS Traffic Sniffer and Analyzer
DNSWatch is a Python-based tool that allows you to sniff and analyze DNS (Domain Name System) traffic on your network. It listens to DNS requests and responses and provides insights into the DNS activity.

## Features

- Sniff and analyze DNS requests and responses.
- Display DNS requests with their corresponding source and destination IP addresses.
- Optional verbose mode for detailed packet inspection.
- Save the results to a specified output file.
- Filter DNS traffic by specifying a victim IP address.
- Analyze DNS types (optional).
- Support for DNS over HTTPS (DoH) (optional).

## Requirements

- Python 3.7+
- scapy 2.4.5 or higher
- colorama 0.4.4 or higher

## Installation

1. Clone this repository:

```bash
git clone https://github.com/HalilDeniz/DNSWatch.git
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```
python dnswatch.py -i <interface> [-v] [-o <output_file>] [-k <victim_ip>] [--analyze-dns-types] [--doh]
```

- `-i`, `--interface`: Specify the network interface to sniff DNS traffic (e.g., "eth0").
- `-v`, `--verbose`: Enable verbose mode for detailed packet inspection (optional).
- `-o`, `--output`: Specify the output file to save the results (optional).
- `-k`, `--victim-ip`: Filter DNS traffic by providing a victim IP address (optional).
- `--analyze-dns-types`: Enable DNS type analysis (optional).
- `--doh`: Use DNS over HTTPS (DoH) for DNS resolution (optional).

Press `Ctrl+C` to stop the sniffing process.

## Examples

- Sniff DNS traffic on interface "eth0":

```bash
python dnssnif.py -i eth0
```

- Sniff DNS traffic on interface "eth0" and save the results to a file:

```bash
python dnssnif.py -i eth0 -o dns_results.txt
```

- Sniff DNS traffic on interface "eth0" and filter requests/responses involving a specific victim IP:

```bash
python dnssnif.py -i eth0 -k 192.168.1.100
```

- Sniff DNS traffic on interface "eth0" and enable DNS type analysis:

```bash
python dnssnif.py -i eth0 --analyze-dns-types
```

- Sniff DNS traffic on interface "eth0" using DNS over HTTPS (DoH):

```bash
python dnssnif.py -i eth0 --doh
```

## License

DNSWatch is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and testing purposes only. It should not be used for any malicious activities.

## Contact

- Email    : halildeniz313@gmail.com
- Linkedin : https://www.linkedin.com/in/halil-ibrahim-deniz/
- TryHackMe: https://tryhackme.com/p/halilovic
- Instagram: https://www.instagram.com/deniz.halil333/
- YouTube  : https://www.youtube.com/c/HalilDeniz
- Mysite   : https://denizhalil.com/

## 💰 You can help me by Donating
[![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/halildeniz) 
[![Patreon](https://img.shields.io/badge/Patreon-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://patreon.com/denizhalil) 

  