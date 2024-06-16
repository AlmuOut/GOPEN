# GOPEN

## Introduction

GOPEN is a pentesting tool that has been developed as a Master final project. It has been written in GO and its main characteristics are the following ones:

* Sniff packets from a LAN.
* Scan ports from a LAN.
* Export packets to a .pcap file.
* Perform a Man in the Middle attack to two targets.
* Perform a DDoS attack to a target.
* Crack a password.

## Usage
It is recommended to use GOPEN in a Local Area Network. \
For cloning:
```
$ git clone https://github.com/AlmuOut/GOPEN.git
$ cd GOPEN
```

Due to some commands of the app that have been written for Linux, GOPEN is only compatible with this OS.\
For building the binary:
```
$ GOOS=Linux GOARCH=Your_Architecture go build -o GOPEN main.go
```

Due to some characteristics as modifying some files in the system, please note that GOPEN would need admin permissions.\
For running the app:
```
$ sudo ./GOPEN
```


## Extra Files
* 10-million-password-list-top-1000000.txt : Dictionary which contains all passwords for cracking hashes.
* hashes.txt : MD5 and SHA2 hashes for cracking password option.
* .pcap files: Results obtained while testing the app.

## Autor
A.O.R.\
aouteda4@alumno.uned.es\
Master in Cybersecurity\
U.N.E.D.\
2023/2024
