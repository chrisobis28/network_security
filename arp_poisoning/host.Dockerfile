FROM debian:bookworm
RUN apt update && apt install net-tools nmap -y
