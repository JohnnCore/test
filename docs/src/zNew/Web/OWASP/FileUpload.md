## delete


# File Upload
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)

## Bypasses
- `Instead of .php, we can use .phar and use ?page=phar://uploads`

- `exiftool -comment="<?php phpinfo(); ?>" nasa.png` - php into image


# Identifying Web Framework
One easy method to determine what language runs the web application is to visit the /index.ext page, where we would swap out ext with various common web extensions, like php, asp, aspx, among others, to see whether any of them exist.

Use [Ffuf](../Fuzzing/Ffuf.md) with this [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) to and replace 'ext'.

Several other techniques may help identify the technologies running the web application, like using the Wappalyzer.

# Bypassing Filters
## Client-Side Validation
### Back-end Request Modification
If we capture the upload request with Burp we can now modify this request to meet our needs without having the front-end type validation restrictions. If the back-end server does not validate the uploaded file type, then we should theoretically be able to send any file type/content, and it would be uploaded to the server.

We modify the filename to shell.php and modify the content to the web shell.

### Disabling Front-end Validation
To start, we can click [CTRL+SHIFT+C] to toggle the browser's Page Inspector, and then click on the profile image, which is where we trigger the file selector for the upload form.

We can remove this function from the HTML code since its primary use appears to be file type validation, and removing it should not break anything.

## Blacklist Filters
### Blacklisting Extensions
### Fuzzing Extensions
As the web application seems to be testing the file extension, our first step is to fuzz the upload functionality with a list of potential extensions and see which of them return the previous error message. Any upload requests that do not return an error message, return a different message, or succeed in uploading the file, may indicate an allowed file extension.

There are many lists of extensions we can utilize in our fuzzing scan. PayloadsAllTheThings provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use SecLists list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).

Then we use Burp Suite Intruder and also un-tick the URL Encoding option to avoid encoding the (.) before the file extension

## Whitelist Filters
### Whitelisting Extensions
### Double Extensions
For example, if the .jpg extension was allowed, we can add it in our uploaded file name and still end our filename with .php (e.g. shell.jpg.php), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.

### Reverse Double Extensions
Intercept a normal allowed upload request, and use the above file name to pass the strict whitelist test

### Character Injection
Finally, let's discuss another method of bypassing a whitelist validation test through Character Injection. We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.

The following are some of the characters we may try injecting:

- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, (shell.php%00.jpg) works with PHP servers with version 5.X or earlier, as it causes the PHP web server to end the file name after the (%00), and store it as (shell.php), while still passing the whitelist. The same may be used with web applications hosted on a Windows server by injecting a colon (:) before the allowed file extension (e.g. shell.aspx:.jpg), which should also write the file as (shell.aspx). Similarly, each of the other characters has a use case that may allow us to upload a PHP script while bypassing the type validation test.

We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the PHP and JPG extensions, as follows:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.php2' '.php3' '.php4' '.php5' '.php6' '.php7' '.pht' '.phtml' '.phar'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

## Type Filters
There are two common methods for validating the file content: Content-Type Header or File Content. Let's see how we can identify each filter and how to bypass both of them.

### Content-Type
We may start by fuzzing the Content-Type header with [SecLists' Content-Type](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/Web/content-type.txt) through Burp Intruder, to see which types are allowed.

Reduce the wordlist to the permitted content. 
```bash
$ cat content-type.txt | grep 'image/' > image-content-types.txt
```

`Note: A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main Content-Type header.`

### MIME-Type
The second and more common type of file content validation is testing the uploaded file's MIME-Type. Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure.

This is usually done by inspecting the first few bytes of the file's content, which contain the File Signature or Magic Bytes. For example, if a file starts with (GIF87a or GIF89a), this indicates that it is a GIF image, while a file starting with plaintext is usually considered a Text file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

Add GIF8 before our PHP code to try to imitate a GIF image while keeping our file extension as .php, so it would execute PHP code regardless.

Also use a real image, keep some of the inital characters and replace the content with the php payload.

# Limited File Uploads
Certain file types, like SVG, HTML, XML, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files. This is why fuzzing allowed file extensions is an important exercise for any file upload attack. It enables us to explore what attacks may be achievable on the web server. So, let's explore some of these attacks.

## XSS
Many file types may allow us to introduce a Stored XSS vulnerability to the web application by uploading maliciously crafted versions of them.

The most basic example is when a web application allows us to upload HTML files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines.

Another example of XSS attacks is web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the Comment or Artist parameters.
```bash
$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' image.jpg
```

When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. Furthermore, if we change the image's MIME-Type to text/html, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.

Finally, XSS attacks can also be carried with SVG images, along with several other attacks. Scalable Vector Graphics (SVG) images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload. For example, we can write the following to svg.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

## XXE
Similar attacks can be carried to lead to XXE exploitation. With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server. The following example can be used for an SVG image that leaks the content of (/etc/passwd):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (/etc/passwd) printed on the page or shown in the page source. Similarly, if the web application allows the upload of XML documents, then the same payload can carry the same attack when the XML data is displayed on the web application.

While reading systems files like /etc/passwd can be very useful for server enumeration, it can have an even more significant benefit for web penetration testing, as it allows us to read the web application's source files. Access to the source code will enable us to find more vulnerabilities to exploit within the web application through Whitebox Penetration Testing. For File Upload exploitation, it may allow us to locate the upload directory, identify allowed extensions, or find the file naming scheme, which may become handy for further exploitation.

To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

Once the SVG image is displayed, we should get the base64 encoded content of index.php, which we can decode to read the source code.

## DoS
Finally, many file upload vulnerabilities may lead to a Denial of Service (DOS) attack on the web server. For example, we can use the previous XXE payloads to achieve DoS attacks.

Furthermore, we can utilize a Decompression Bomb with file types that use data compression, like ZIP archives. If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can eventually lead to many Petabytes of data, resulting in a crash on the back-end server.

Another possible DoS attack is a Pixel Flood attack with some image files that utilize image compression, like JPG or PNG. We can create any JPG image file with any image size (e.g. 500x500), and then manually modify its compression data to say it has a size of (0xffff x 0xffff), which results in an image with a perceived size of 4 Gigapixels. When the web application attempts to display the image, it will attempt to allocate all of its memory to this image, resulting in a crash on the back-end server.

In addition to these attacks, we may try a few other methods to cause a DoS on the back-end server. One way is uploading an overly large file, as some upload forms may not limit the upload file size or check for it before uploading it, which may fill up the server's hard drive and cause it to crash or slow down considerably.

If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. ../../../etc/passwd), which may also cause the server to crash. Try to search for other examples of DOS attacks through a vulnerable file upload functionality.

