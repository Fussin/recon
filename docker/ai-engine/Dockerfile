# AI engine with GPU support:
FROM nvidia/cuda:12.0-base-ubuntu22.04

# Python environment setup
RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install torch torchvision torchaudio --extra-index-url https://download.pytorch.org/whl/cu120
RUN pip3 install transformers

# Model downloads and caching
# ...

# GPU optimization configurations
# ...
