FROM debian:bookworm
RUN apt update && apt install net-tools curl iputils-ping -y
