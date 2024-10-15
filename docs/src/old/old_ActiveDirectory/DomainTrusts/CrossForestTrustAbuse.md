# Attacking Domain Trusts - Cross-Forest Trust Abuse
## Windows
### Cross-Forest Kerberoasting
Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts, depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional domain/forest trust, you can likely perform various attacks to gain a foothold. Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.

We can utilize PowerView to enumerate accounts in a target domain that have SPNs associated with them.

#### Enumerating Accounts for Associated SPNs Using Get-DomainUser
```
PS > Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```

#### Enumerating the mssqlsvc Account
```
PS > Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
```

Let's perform a Kerberoasting attack across the trust using Rubeus. We run the tool as we did in the Kerberoasting section, but we include the /domain: flag and specify the target domain.

#### Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
```
PS > .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

We could then run the hash through Hashcat. If it cracks, we've now quickly expanded our access to fully control two domains by leveraging a pretty standard attack and abusing the authentication direction and setup of the bidirectional forest trust.

### Admin Password Re-Use & Group Membership
From time to time, we'll run into a situation where there is a bidirectional forest trust managed by admins from the same company. If we can take over Domain A and obtain cleartext passwords or NT hashes for either the built-in Administrator account (or an account that is part of the Enterprise Admins or Domain Admins group in Domain A), and Domain B has a highly privileged account with the same name, then it is worth checking for password reuse across the two forests. I occasionally ran into issues where, for example, Domain A would have a user named adm_bob.smith in the Domain Admins group, and Domain B had a user named bsmith_admin. Sometimes, the user would be using the same password in the two domains, and owning Domain A instantly gave me full admin rights to Domain B.

We may also see users or admins from Domain A as members of a group in Domain B. Only Domain Local Groups allow security principals from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership.

We can use the PowerView function Get-DomainForeignGroupMember to enumerate groups with users that do not belong to the domain, also known as foreign group membership. Let's try this against the FREIGHTLOGISTICS.LOCAL domain with which we have an external bidirectional forest trust.

#### Using Get-DomainForeignGroupMember
```
PS > Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
PS > Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
```

#### Accessing DC03 Using Enter-PSSession
```
PS > Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

From the command output above, we can see that we successfully authenticated to the Domain Controller in the FREIGHTLOGISTICS.LOCAL domain using the Administrator account from the INLANEFREIGHT.LOCAL domain across the bidirectional forest trust. This can be a quick win after taking control of a domain and is always worth checking for if a bidirectional forest trust situation is present during an assessment and the second forest is in-scope.

## Linux
If this is possible in the environment we are assessing, we can perform this with GetUserSPNs.py from our Linux attack host. To do this, we need credentials for a user that can authenticate into the other domain and specify the -target-domain flag in our command. Performing this against the FREIGHTLOGISTICS.LOCAL domain, we see one SPN entry for the mssqlsvc account.

### Cross-Forest Kerberoasting
#### Using GetUserSPNs.py
```
$ GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
transporter@4
Rerunning the command with the -request flag added gives us the TGS ticket. We could also add -outputfile <OUTPUT FILE> to output directly into a file that we could then turn around and run Hashcat against.

#### Using the -request Flag
```
$ GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley  
```

### Hunting Foreign Group Membership with Bloodhound-python
As noted in the last section, we may, from time to time, see users or admins from one domain as members of a group in another domain. Since only Domain Local Groups allow users from outside their forest, it is not uncommon to see a highly privileged user from Domain A as a member of the built-in administrators group in domain B when dealing with a bidirectional forest trust relationship. If we are testing from a Linux host, we can gather this information by using the Python implementation of BloodHound. We can use this tool to collect data from multiple domains, ingest it into the GUI tool and search for these relationships.

On some assessments, our client may provision a VM for us that gets an IP from DHCP and is configured to use the internal domain's DNS. We will be on an attack host without DNS configured in other instances. In this case, we would need to edit our resolv.conf file to run this tool since it requires a DNS hostname for the target Domain Controller instead of an IP address. We can edit the file as follows using sudo rights. Here we have commented out the current nameserver entries and added the domain name and the IP address of ACADEMY-EA-DC01 as the nameserver.

```
$ cat /etc/resolv.conf 

domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

### Connect to 
```
psexec.py FREIGHTLOGISTICS.LOCAL/sapsso@academy-ea-dc03.inlanefreight.local -target-ip 172.16.5.238
```

#### Running bloodhound-python Against INLANEFREIGHT.LOCAL
```
$ bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```

#### Compressing the File with zip -r
```
$ zip -r ilfreight_bh.zip *.json
```

We will repeat the same process, this time filling in the details for the FREIGHTLOGISTICS.LOCAL domain.


#### Adding FREIGHTLOGISTICS.LOCAL Information to /etc/resolv.conf
```
$ cat /etc/resolv.conf 

domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

#### Running bloodhound-python Against FREIGHTLOGISTICS.LOCAL
```
$ bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```

After uploading the second set of data (either each JSON file or as one zip file), we can click on Users with Foreign Domain Group Membership under the Analysis tab and select the source domain as INLANEFREIGHT.LOCAL. Here, we will see the built-in Administrator account for the INLANEFREIGHT.LOCAL domain is a member of the built-in Administrators group in the FREIGHTLOGISTICS.LOCAL domain as we saw previously.