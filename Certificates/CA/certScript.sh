#!/bin/bash
name="nurse1"
division="surgery"
occupation="nurse" #Doctor/Patient/Nurse/Government
password="password"

keytool -keystore ${name} -genkey -keypass $password -storepass $password -alias $name -dname "CN=$name, OU=$division, O=$occupation"
keytool -keystore ${name} -certreq -alias $name -keyalg rsa -file ${name}.csr -storepass $password
openssl x509 -req -in ${name}.csr -CA CA.pem -CAkey CAkey.pem -CAcreateserial -out ${name}Signed.pem -passin pass:password
rm CA.srl
rm ${name}.csr
echo y | keytool -import -keystore ${name} -file CA.pem -alias CA -storepass $password
keytool -import -keystore ${name} -file ${name}Signed.pem -alias $name -storepass $password
rm ${name}Signed.pem
