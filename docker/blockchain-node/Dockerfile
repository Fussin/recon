# Blockchain integration service
FROM ubuntu:22.04

# Ethereum client setup
RUN apt-get update && apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get update && apt-get install -y ethereum

# Smart contract compilation
RUN apt-get install -y solc

# IPFS node configuration
RUN apt-get install -y ipfs
RUN ipfs init
