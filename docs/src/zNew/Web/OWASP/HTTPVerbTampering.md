## delete


# HTTP Verb Tampering
An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods. This can be exploited by sending malicious requests using unexpected methods, which may lead to bypassing the web application's authorization mechanism or even bypassing its security controls against other web attacks. HTTP Verb Tampering attacks are one of many other HTTP attacks that can be used to exploit web server configurations by sending malicious HTTP requests.

# Attack
Intercept request with Burp and change method to OPTIONS/POST/PUT/GET/PATCH(change request method burp option)

# Bypassing Basic Authentication
Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. While many automated vulnerability scanning tools can consistently identify HTTP Verb Tampering vulnerabilities caused by insecure server configurations, they usually miss identifying HTTP Tampering vulnerabilities caused by insecure coding. This is because the first type can be easily identified once we bypass an authentication page, while the other needs active testing to see whether we can bypass the security filters in place.

# Bypassing Security Filters
The other and more common type of HTTP Verb Tampering vulnerability is caused by Insecure Coding errors made during the development of the web application, which lead to web application not covering all HTTP methods in certain functionalities. This is commonly found in security filters that detect malicious requests. For example, if a security filter was being used to detect injection vulnerabilities and only checked for injections in POST parameters (e.g. $_POST['parameter']), it may be possible to bypass it by simply changing the request method to GET.

## Identify
No matter what we try, the web application properly blocks our requests and is secured against injection attempts. However, we may try an HTTP Verb Tampering attack to see if we can bypass the security filter altogether.

## Exploit
To try and exploit this vulnerability, let's intercept the request in Burp Suite (Burp) and then use Change Request Method to change it to another method.

To confirm whether we bypassed the security filter, we need to attempt exploiting the vulnerability the filter is protecting