from scapy.all import *

#packet[Ether].src macs destino
#packet[IP].src ips
# packet.type : 2048
# packet[IP].payload te da el protocolo de capa 3 + a la pagina que accedio 
# te da el paquete de capa superior que está encapsulado
# ARP in packet te dice los protocolos presentes

def main():
    pcap_path = "Lucy_Wifi_Casa/LucyCasa.pcapng"
    paq_path = "Lucy_Wifi_Casa/fuente_ent_info_LucyCasa.txt"

    paq_file = open(paq_path, "w")
    for packet in PcapReader(pcap_path):
        if IP in packet:
            paq_file.write(str(packet[IP].show) + "\n")

if __name__ == "__main__":
    main()