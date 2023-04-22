from scapy.all import *

#packet[Ether].src macs destino
#packet[IP].src ips
# packet.type : 2048
# packet[IP].payload te da el protocolo de capa 3 + a la pagina que accedio 
# te da el paquete de capa superior que está encapsulado
# ARP in packet te dice los protocolos presentes

def main():
    pcap_path = "cafeteria/v4.pcapng"
    paq_path = "cafeteria/ARPS.txt"

    paq_file = open(paq_path, "w", encoding="utf-8")
    for packet in PcapReader(pcap_path):
        if ARP in packet:
            paq_file.write(str(packet[ARP].show) + "\n")

if __name__ == "__main__":
    main()