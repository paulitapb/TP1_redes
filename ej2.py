from scapy.all import *

pcap_path = "Lucy_Wifi_Casa/LucyCasa.pcapng" 
#pcap_path = input("enter file to sniff:")
ouput_file = open(pcap_path.split('/')[0] +"/fuenteEj2_sim2" + pcap_path.split('/')[1].split('.')[0] + ".txt", "w")

pcap_file = rdpcap(pcap_path)

S2 = {}

def calcularEntropia(simbolos, N):
    suma = 0
    prob = 0
    for d,k in simbolos:
        prob = k/N
        informacion_evento = -math.log(prob, 2)
        suma += prob * informacion_evento
        print("%s : %.5f" % (d,k/N)) #mostrar simb + proba
        ouput_file.write("%s,%.5f " % (d,k/N))
        
        print("%.5f" % informacion_evento)
        ouput_file.write("Informacion del evento: %.5f \n" % informacion_evento)
    return suma

def mostrar_fuente(S):
    global cantidadTramas
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    
    entropia = calcularEntropia(simbolos, N)
    ouput_file.write("Entropia: %f \n"% entropia)
    print("Entropia: %f \n"% entropia)
    print("--------------------------")

    
def callback(pkt):
    
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        proto = pkt[Ether].type # El campo type del frame tiene el protocolo

        if proto == 2054:
            s_i = (pkt[ARP].psrc, pkt[ARP].op) # Aca se define el simbolo de la fuente
            
            if s_i not in S2:
                S2[s_i] = 0.0
            S2[s_i] += 1.0
            mostrar_fuente(S2) 

#
def main():
    sniff(offline=pcap_file,prn=callback)

if __name__ == "__main__":
    main()