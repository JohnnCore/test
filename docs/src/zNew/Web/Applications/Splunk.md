# Discovery/Footprinting
We can discover Splunk with a quick Nmap service scan. Here we can see that Nmap identified the Splunkd httpd service on port 8000 and port 8089, the Splunk management port for communication with the Splunk REST API.

# Enumeration
https://<IP>:<PORT>/en-US/app/launcher/home

Splunk has multiple ways of running code, such as server-side Django applications, REST endpoints, scripted inputs, and alerting scripts. A common method of gaining remote code execution on a Splunk server is through the use of a scripted input. These are designed to help integrate Splunk with data sources such as APIs or file servers that require custom methods to access. Scripted inputs are intended to run these scripts, with STDOUT provided as input to Splunk.

As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts. Also, every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system. A quick way to gain RCE is by creating a scripted input that tells Splunk to run a Python reverse shell script. We'll cover this in the next section.

Aside from this built-in functionality, Splunk has suffered from various public vulnerabilities over the years, such as this SSRF that could be used to gain unauthorized access to the Splunk REST API. At the time of writing, Splunk has 47 CVEs. If we perform a vulnerability scan against Splunk during a penetration test, we will often see many non-exploitable vulnerabilities returned. This is why it is important to understand how to abuse built-in functionality.

# Attacking Splunk
We can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us. The bin directory in this repo has examples for Python and PowerShell. Let's walk through this step-by-step. 

```bash
$ tar -cvzf updater.tar.gz splunk_shell/
```

The next step is to choose Install app from file and upload the application.

