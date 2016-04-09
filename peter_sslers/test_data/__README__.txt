The self-signed certs were trivially created:

================================================================================

openssl genrsa -out selfsigned_1-server.key 1024
openssl req -new -sha256 -key selfsigned_1-server.key -subj "/CN=selfsigned-1.example.com" -out selfsigned_1-server.csr
openssl x509 -req -days 365 -in selfsigned_1-server.csr -signkey selfsigned_1-server.key -out selfsigned_1-server.crt

openssl genrsa -out selfsigned_2-server.key 1024
openssl req -new -sha256 -key selfsigned_2-server.key -subj "/CN=selfsigned-2.example.com" -out selfsigned_2-server.csr
openssl x509 -req -days 365 -in selfsigned_2-server.csr -signkey selfsigned_2-server.key -out selfsigned_2-server.crt

openssl genrsa -out selfsigned_3-server.key 1024
openssl req -new -sha256 -key selfsigned_3-server.key -subj "/CN=selfsigned-3.example.com" -out selfsigned_3-server.csr
openssl x509 -req -days 365 -in selfsigned_3-server.csr -signkey selfsigned_3-server.key -out selfsigned_3-server.crt

openssl genrsa -out selfsigned_4-server.key 1024
openssl req -new -sha256 -key selfsigned_4-server.key -subj "/CN=selfsigned-4.example.com" -out selfsigned_4-server.csr
openssl x509 -req -days 365 -in selfsigned_4-server.csr -signkey selfsigned_4-server.key -out selfsigned_4-server.crt

openssl genrsa -out selfsigned_5-server.key 1024
openssl req -new -sha256 -key selfsigned_5-server.key -subj "/CN=selfsigned-5.example.com" -out selfsigned_5-server.csr
openssl x509 -req -days 365 -in selfsigned_5-server.csr -signkey selfsigned_5-server.key -out selfsigned_5-server.crt


================================================================================

A more detailed way to make them:

# generate the key
# set the pass to pass, strip before signing
# make sure to enter data for Common Name (e.g. server FQDN or YOUR name) []:www.example.com
openssl genrsa -des3 -out selfsigned_1-server.key 1024
mv selfsigned_1-server.key selfsigned_1-server.key.pass
openssl rsa -in selfsigned_1-server.key.pass -out selfsigned_1-server.key
openssl req -new -sha256 -key selfsigned_1-server.key -subj "/CN=example.com" -out selfsigned_1-server.csr
openssl x509 -req -days 365 -in selfsigned_1-server.csr -signkey selfsigned_1-server.key -out selfsigned_1-server.crt

