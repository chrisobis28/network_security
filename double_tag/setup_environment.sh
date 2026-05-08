#!/bin/bash
set -eux

echo 'Setting up interfaces'

ip link add vlan_br0 type bridge
ip link add vlan_br1 type bridge

ip link set vlan_br0 type bridge vlan_filtering 1
ip link set vlan_br1 type bridge vlan_filtering 1
ip link add vlan_trunk0 type veth peer name vlan_trunk1

ip link set vlan_trunk0 master vlan_br0
ip link set vlan_trunk1 master vlan_br1
bridge vlan add dev vlan_trunk0 vid 20 master
bridge vlan add dev vlan_trunk1 vid 20 master

ip link add vlan_veth0 type veth peer name vlan_veth0_br
ip link set vlan_veth0_br master vlan_br0

ip link add vlan_veth1 type veth peer name vlan_veth1_br
ip link set vlan_veth1_br master vlan_br1

bridge vlan add dev vlan_veth1_br vid 20 pvid untagged master
bridge vlan del dev vlan_veth1_br vid 1 pvid untagged master

ip link set up dev vlan_br0
ip link set up dev vlan_br1 up
ip link set up dev vlan_trunk0 up
ip link set up dev vlan_trunk1 up
ip link set up dev vlan_veth0 up
ip link set up dev vlan_veth0_br up
ip link set up dev vlan_veth1 up
ip link set up dev vlan_veth1_br up

echo 'Creating containers'

docker compose up -d --build

echo 'Done!'
