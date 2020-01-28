https://stackoverflow.com/questions/21297139/how-do-you-sign-a-certificate-signing-request-with-your-certification-authority/21340898#21340898

mkdir generated
echo '01' > serial.txt
touch index.txt


1. Make the CACert

openssl req -x509 -config ./openssl-ca-1.cnf -newkey rsa:4096 -sha256 -nodes -out cacert.pem -outform PEM

2. Sign a CSR

openssl ca -batch -config ./openssl-ca-2.cnf -policy signing_policy -extensions signing_req -out mygenerated.pem -infiles a.csr