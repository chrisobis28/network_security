#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
nginx
/opt/knock.py
