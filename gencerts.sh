#!/bin/sh
set -eux
dir="$(dirname "$0")/certs"
mkdir -p -- "$dir"
cd -- "$dir"
openssl req -x509 -subj "/O=Test CA/CN=Test Root" -nodes -sha256 -days 3650 -newkey rsa:2048 -out root.crt -keyout root.key
openssl req -new -subj "/O=Test CA/CN=testca.test" -nodes -sha256 -days 3650 -newkey rsa:2048 -out web.csr -keyout web.key
openssl x509 -req -CA root.crt -CAkey root.key -CAcreateserial -in web.csr -out web.crt
openssl req -x509 -subj "/O=Test CA/OU=Test Client CA v1" -nodes -sha1 -days 73000 -newkey rsa:1024 -out client.crt -keyout client.key
