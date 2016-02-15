#!/bin/bash
name="NameNamesson"
occupation="Doctor" #Doctor/Patient/Nurse/Government
division="Surgery"
password="password"

keytool -keystore ${name}keystore -genkey -keypass $password -storepass $password -alias $name -dname "CN=$name, OU=$occupation, O=$division"
keytool -keystore ${name}keystore -certreq -alias $name -keyalg rsa -file ${name}.csr -storepass $password
openssl x509 -req -in ${name}.csr -CA CA.pem -CAkey CAkey.pem -CAcreateserial -out ${name}Signed.pem -passin pass:password
rm CA.srl
rm ${name}.csr
echo y | keytool -import -keystore ${name}keystore -file CA.pem -alias CA -storepass $password
keytool -import -keystore ${name}keystore -file ${name}Signed.pem -alias $name -storepass $password
rm ${name}Signed.pem
