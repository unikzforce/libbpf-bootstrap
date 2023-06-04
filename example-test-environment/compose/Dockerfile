FROM ubuntu:latest

# Update the package repositories and install required packages
RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \ 
        build-essential \
        pkg-config \
        clang \
        llvm \
        m4 \
        git \
        libelf-dev \
        libpcap-dev \
        iproute2 \
        tshark \
        iputils-ping \
        linux-headers-generic \
        gcc-multilib \
        linux-libc-dev \
        linux-cloud-tools-generic \
        linux-cloud-tools-common \
        linux-tools-common \
        linux-tools-generic

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git

RUN make -C bpftool/src/ install

RUN git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git

RUN make -C /xdp-tools/ install

# Set the default command
CMD ["tail", "-f", "/dev/null"]
