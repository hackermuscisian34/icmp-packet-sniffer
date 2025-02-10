from scapy.all import sniff, ICMP

def packet_callback(packet):
    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        if icmp_type == 8:
            print("Captured ICMP Echo Request (Ping Request)")
        elif icmp_type == 0:
            print("Captured ICMP Echo Reply (Ping Reply)")

print("Sniffing ICMP packets...")
sniff(filter="icmp", prn=packet_callback, store=0)