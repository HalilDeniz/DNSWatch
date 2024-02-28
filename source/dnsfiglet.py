import pyfiglet
from colorama import init, Fore

# colorama'yı başlat
init(autoreset=True)

def dnsfiglet():
    metin = "DNS Packet Sniffer started..."
    figlet_yazi = pyfiglet.figlet_format(metin, font="slant")

    return print(Fore.GREEN + figlet_yazi)
