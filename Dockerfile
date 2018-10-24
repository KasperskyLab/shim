FROM ubuntu:18.04

RUN apt-get update && \
    apt-get -y install gcc=4:7.3.0-3ubuntu2.1 && \
    apt-get -y install gnu-efi=3.0.8-0ubuntu1~18.04.1 && \
    apt-get -y install make=4.1-9.1ubuntu1 && \
    apt-get -y install git

COPY . /build
WORKDIR /build

CMD make EFI_PATH=/usr/lib VENDOR_CERT_FILE=KLFDEEV_2017.cer DEFAULT_LOADER=\\\\\\\\kl_main.efi && \
    chmod -x /build/shimx64.efi && \
    sha256sum /build/shimx64.efi && \
    cp /build/shimx64.efi /out
