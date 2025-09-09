FROM handsonsecurity/seed-ubuntu:large

RUN apt-get update && apt-get install -y python3-pip iperf3 git astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

COPY requirements.txt /requirements.txt
RUN pip3 install --no-cache-dir -r /requirements.txt

# LibOQS-Python does not have a package on the pip respository. It has to be installed manually.
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
WORKDIR /liboqs-python

# Runs a test script after instaling the package to download the actual OQS library.
RUN pip3 install . && python3 examples/kem.py



