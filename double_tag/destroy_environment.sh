#!/bin/bash
set -x

docker compose down

ip link del vlan_br0
ip link del vlan_br1
ip link del vlan_veth0
ip link del vlan_veth1
ip link del vlan_trunk0
