# Harvesting Kerberos Tickets
We need a valid Kerberos ticket to perform a Pass the Ticket (PtT). It can be:

    - Service Ticket (TGS - Ticket Granting Service) to allow access to a particular resource.
    - Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.

Before we perform a Pass the Ticket (PtT) attack, let's see some methods to get a ticket using [Mimikatz](https://github.com/ParrotSec/mimikatz) and [Rubeus](https://github.com/GhostPack/Rubeus).


On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

=== "Mimikatz"
    We can harvest all tickets from a system using the Mimikatz module sekurlsa::tickets /export. The result is a list of files with the extension .kirbi, which contain the tickets.

    ```
    # Export Tickets
    > mimikatz.exe
    > privilege::debug
    > sekurlsa::tickets /export
    > exit
    > dir *.kirbi
    ```

    The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an @ that separates the service name and the domain, for example: [randomvalue]-username@service-domain.local.kirbi.

    !!! Note
        If you pick a ticket with the service krbtgt, it corresponds to the TGT of that account.

    ```
    ren "[0;38319]-2-0-40e10000-tpetty@krbtgt-INLANEFREIGHT.LOCAL.kirbi" new.kirbi  
    ```

    !!! Note
        At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.

=== "Rubeus"
    We can also export tickets using Rubeus and the option dump. This option can be used to dump all tickets (if running as a local administrator). Rubeus dump, instead of giving us a file, will print the ticket encoded in base64 format. We are adding the option /nowrap for easier copy-paste.

    ```
    #  Export Tickets
    > Rubeus.exe dump /nowrap
    ```

!!! Note
    To collect all tickets we need to execute Mimikatz or Rubeus as an administrator.

This is a common way to retrieve tickets from a computer. Another advantage of abusing Kerberos tickets is the ability to forge our own tickets. Let's see how we can do this using the [OverPass the Hash or Pass the Key](./PassTheKeyOverPassTheHash.md) technique.
