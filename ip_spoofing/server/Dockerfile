FROM ubuntu:20.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python2 iptables-persistent nginx tcpdump
COPY rules.v4 /etc/iptables/rules.v4
COPY entrypoint.sh /entrypoint.sh
COPY icmp_knock.py /opt/knock.py 
COPY index.html /var/www/html/index.html
RUN chmod +x /entrypoint.sh /opt/knock.py
