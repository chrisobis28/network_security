#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
tail -F anything
