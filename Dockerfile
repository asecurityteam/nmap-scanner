FROM debian:latest AS BASE
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl bzip2 build-essential libssl-dev

#######################################

FROM BASE as NMAP
ARG NMAP_VERSION="7.70"
RUN curl -vs -o "nmap-${NMAP_VERSION}.tar.bz2" "https://nmap.org/dist/nmap-7.70.tar.bz2" && \
    bzip2 -cd "nmap-${NMAP_VERSION}.tar.bz2" | tar xvf - && \
    cd "nmap-${NMAP_VERSION}" && \
    ./configure && \
    make && \
    su root && \
    make install

##########################################

FROM NMAP AS VULDB
ARG VULDB_VERSION="2.0"
RUN mkdir -p /usr/local/share/nmap/scripts/vulscan/ && \
    curl -vs -o "/tmp/vulscan.tar.gz" \
    "https://www.computec.ch/projekte/vulscan/download/nmap_nse_vulscan-${VULDB_VERSION}.tar.gz" && \
    tar xzvf "/tmp/vulscan.tar.gz" -C "/usr/local/share/nmap/scripts/" && \
    rm "/tmp/vulscan.tar.gz"

############################################3

FROM asecurityteam/sdcli:v1 AS GOBUILDER
RUN mkdir -p /go/src/github.com/asecurityteam/nmap-scaner
WORKDIR /go/src/github.com/asecurityteam/nmap-scanner
COPY --chown=sdcli:sdcli . .
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build -a -o /opt/app main.go

##################################

FROM VULDB AS RUNTIME
COPY --from=GOBUILDER /opt/app /opt/app
COPY scripts/* /usr/local/share/nmap/scripts/custom/
ENTRYPOINT ["/opt/app"]
