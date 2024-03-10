FROM ghcr.io/termux/package-builder:latest
RUN cd /home/builder && git clone https://github.com/termux/termux-packages.git
