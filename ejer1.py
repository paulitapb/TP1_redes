from scapy.all import *

S1 = {}
def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("\n".join([ " %s : %.5f" % (d,k/N) for d,k in simbolos ]))
    print()

def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = (dire, proto) # Aca se define el simbolo de la fuente
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0
    mostrar_fuente(S1)

def main():
    pcap_path = "red_wifi_UBA_Labo3.pcapng"
    pcap_file = rdpcap(pcap_path)
    sniff(offline=pcap_file,prn=callback)

if __name__ == "__main__":
    main()