from scapy.all import sniff, ICMP

def packet_callback(pkt):
    print(f"Received: {pkt.summary()}")
    if ICMP in pkt:
        print(f"  ICMP Type: {pkt[ICMP].type}, ID: {pkt[ICMP].id}")

print("Listening on eth0 for ANY packets...")
sniff(iface="eth0", prn=packet_callback, store=False, timeout=15)
print("Done")