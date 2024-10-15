# Domain Trusts
## Enumerating Trust Relationships
### Using Get-ADTrust
```
PS > Import-Module activedirectory
PS > Get-ADTrust -Filter *
```

Aside from using built-in AD tools such as the Active Directory PowerShell module, both PowerView and BloodHound can be utilized to enumerate trust relationships, the type of trusts established, and the authentication flow. After importing PowerView, we can use the Get-DomainTrust function to enumerate what trusts exist, if any.

### Checking for Existing Trusts using Get-DomainTrust
```
PS > Get-DomainTrust 
```

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional). This information is beneficial once a foothold is obtained, and we plan to compromise the environment further.

### Using Get-DomainTrustMapping
```
PS > Get-DomainTrustMapping
```

From here, we could begin performing enumeration across the trusts. For example, we could look at all users in the child domain:

### Checking Users in the Child Domain using Get-DomainUser
```
PS > Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

### Using netdom to query domain trust
```
> netdom query /domain:inlanefreight.local trust
```

### Using netdom to query domain controllers
```
> netdom query /domain:inlanefreight.local dc
```

### Using netdom to query workstations and servers
```
> netdom query /domain:inlanefreight.local workstation
```

### Visualizing Trust Relationships in BloodHound
We can also use BloodHound to visualize these trust relationships by using the Map Domain Trusts pre-built query. Here we can easily see that two bidirectional trusts exist.

