#!/bin/bash
chmod +x quic_*
./quic_server --certificate_file=certs/leaf_cert.pem --key_file=certs/leaf_cert.pkcs8 --quic_in_memory_cache_dir=www --port=6121 --fec --lossless --fifo &
./quic_server --certificate_file=certs/leaf_cert.pem --key_file=certs/leaf_cert.pkcs8 --quic_in_memory_cache_dir=www --port=6122 --lossless --fifo &
python ../Tests/tcp_server.py file.txt

