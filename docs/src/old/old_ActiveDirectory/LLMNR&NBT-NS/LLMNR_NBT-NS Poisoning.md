# LLMNR/NBT-NS Poisoning 
Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain. SMB Relay attacks will be covered in a later module about Lateral Movement.


## Linux
### Starting Responder [https://github.com/lgandx/Responder]
```
$ sudo responder -I ens224 
$ sudo responder -I ens224 -w -d
```

/usr/share/responder/logs

### Cracking an NTLMv2 Hash With Hashcat
```
$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt 
```

# LLMNR/NBT-NS Poisoning
## Windows
### Inveigh [https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1]
If we end up with a Windows host as our attack box, our client provides us with a Windows box to test from, or we land on a Windows host as a local admin via another attack method and would like to look to further our access, the tool Inveigh works similar to Responder

Press ESC to enter/exit
help
```
PS > Import-Module .\Inveigh.ps1
PS > (Get-Command Invoke-Inveigh).Parameters

PS > Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### C# Inveigh (InveighZero) [https://github.com/Kevin-Robertson/Inveigh/tree/master]

Press ESC to enter/exit
help
```
PS > .\Inveigh.exe
```