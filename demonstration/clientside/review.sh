#!/bin/bash
echo "add patient1 doctor1"
java -jar client.jar localhost 14922 add patient1 doctor1
read

echo "write patient1 doctor1"
java -jar client.jar localhost 14922 write patient1 doctor1
read

echo "read patient1 nurse1"
java -jar client.jar localhost 14922 read patient1 nurse1
read

echo "read patient1 nurse2"
java -jar client.jar localhost 14922 read patient1 nurse2
read

echo "read patient1 patient1"
java -jar client.jar localhost 14922 read patient1 patient1
read

echo "delete patient1 government"
java -jar client.jar localhost 14922 delete patient1 government
read

echo "read patient1 doctor1"
java -jar client.jar localhost 14922 read patient1 doctor1
