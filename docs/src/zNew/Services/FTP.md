## delete


# Interacting
## Connecting
```bash
$ ftp <USER>@<IP> <PORT>
```

```bash
$ openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

## Recursive Listing
```bash
ftp> ls -R
```

## Download Files
```bash
ftp> get Notes.txt
```

## Download All Available Files
```bash
$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

## Upload a File
```bash
ftp> put testupload.txt 
``` 

# Footprinting
## Nmap
```bash
$ sudo nmap --script-updatedb
$ sudo nmap -sC -sV -A -p 21 192.168.2.142
```

## FTP Bounce Attack
An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network. The attacker uses a PORT command to trick the FTP connection into running commands and getting information from a device other than the intended server.

Consider we are targetting an FTP Server FTP_DMZ exposed to the internet. Another device within the same network, Internal_DMZ, is not exposed to the internet. We can use the connection to the FTP_DMZ server to scan Internal_DMZ using the FTP Bounce attack and obtain information about the server's open ports. Then, we can use that information as part of our attack against the infrastructure.

The Nmap -b flag can be used to perform an FTP bounce attack:

```bash
$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2`
```