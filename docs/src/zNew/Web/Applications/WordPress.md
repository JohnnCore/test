# Discovery/Footprinting
A quick way to identify a WordPress site is by browsing to the /robots.txt

# Enumeration
Viewing the page with cURL and grepping for WordPress can help us confirm that WordPress is in use and footprint the version number, which we should note down for later.
```bash
$ curl -s http://blog.inlanefreight.local | grep WordPress
$ curl -s http://blog.inlanefreight.local/ | grep themes
$ curl -s http://blog.inlanefreight.local/ | grep plugins
```

Checking the page source of another page



## Enumerating Users
We can do some manual enumeration of users as well. As mentioned earlier, the default WordPress login page can be found at /wp-login.php.


A valid username and an invalid password results in the following message:
`Error: The password you entered for the username <username> is incorrect. Lost your password?`

However, an invalid username returns that the user was not found.
`The username <username> is not registered on this site. If you are unsure of your username, try your email address instead.`

# WPScan
WPScan is an automated WordPress scanner and enumeration tool. It determines if the various themes and plugins used by a blog are outdated or vulnerable 

WPScan is also able to pull in vulnerability information from external sources. We can obtain an API token from [WPVulnDB](https://wpscan.com/profile/), which is used by WPScan to scan for PoC and reports. The free plan allows up to 75 requests per day. To use the WPVulnDB database, just create an account and copy the API token from the users page. This token can then be supplied to wpscan using the --api-token parameter.

```bash
$ sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>
```

# Attacking
## Login Bruteforce
WPScan can be used to brute force usernames and passwords.
The tool uses two kinds of login brute force attacks, xmlrpc and wp-login. The wp-login method will attempt to brute force the standard WordPress login page, while the xmlrpc method uses WordPress API to make login attempts through /xmlrpc.php. The xmlrpc method is preferred as it’s faster.
```bash
$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

