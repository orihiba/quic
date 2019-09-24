#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_file> <m> <k>"
    exit 1
fi

FILE_NAME=$1
M=$2
K=$3

chmod +x quic_*
./quic_server --certificate_file=certs/leaf_cert.pem --key_file=certs/leaf_cert.pkcs8 --quic_in_memory_cache_dir=www --port=6121 --fec --lossless --fifo --input_file=$FILE_NAME --m=$M --k=$K &
./quic_server --certificate_file=certs/leaf_cert.pem --key_file=certs/leaf_cert.pkcs8 --quic_in_memory_cache_dir=www --port=6122 --lossless --fifo --input_file=$FILE_NAME &
python ../Tests/tcp_server.py $FILE_NAME &

