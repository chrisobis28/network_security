from scapy.all import *

# VLAN Hopping - when an attacker escapes their assigned VLAN and sends traffic into another VLAN
# 1. Switch spoofing - attacker tricks a switch port into becoming a trunk port;
# Trunk ports carry traffic for multiple VLANs; normally used between switches, not for ordinary hosts
# 2. Double tagging