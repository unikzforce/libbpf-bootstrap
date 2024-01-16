FROM ubuntu:latest

# Update the package repositories and install required packages
RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

RUN apt install -y pkg-config
RUN apt install -y build-essential
RUN apt install -y clang
RUN apt install -y llvm
RUN apt install -y m4
RUN apt install -y git
RUN apt install -y libelf-dev
RUN apt install -y libpcap-dev
RUN apt install -y iproute2
RUN apt install -y iputils-ping
RUN apt install -y linux-headers-generic
#RUN apt install -y gcc-multilib-arm-linux-gnueabi
RUN apt install -y linux-libc-dev
#RUN apt install -y linux-cloud-tools-generic
RUN apt install -y linux-cloud-tools-common
RUN apt install -y linux-tools-common
RUN apt install -y linux-tools-generic
RUN apt install -y cmake
RUN apt install -y cargo
RUN apt install -y libpcap-dev
RUN apt install -y libcap-ng-dev
RUN apt install -y libbfd-dev
RUN apt install -y libcap-dev
RUN ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

RUN mkdir /sources/

WORKDIR /sources/

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git

RUN make -C bpftool/src/ install

RUN git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git

RUN make -C xdp-tools/ install

RUN git clone --recurse-submodules https://github.com/unikzforce/libbpf-bootstrap

RUN mkdir libbpf-bootstrap/build

WORKDIR /sources/libbpf-bootstrap/build/

RUN cmake ../examples/c

RUN make

WORKDIR /sources/libbpf-bootstrap/examples/rust/xdp_switch

RUN cargo build --release

# Set the default command
CMD ["tail", "-f", "/dev/null"]
