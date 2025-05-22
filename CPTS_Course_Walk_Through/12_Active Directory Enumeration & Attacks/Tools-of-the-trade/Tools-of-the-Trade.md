# 📦 Tools of the Trade

Trong các phần của module, bạn sẽ sử dụng các công cụ mã nguồn mở hoặc nhị phân được biên dịch sẵn. Tùy theo hệ điều hành, các công cụ này sẽ được cài sẵn trên:

- `C:\Tools` với Windows.
- Parrot Linux tùy chỉnh với đầy đủ script và công cụ cho các tấn công từ máy Linux trong mạng nội bộ.

Dưới đây là danh sách các công cụ phổ biến được sử dụng:

| Tool | Description |
|------|-------------|
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) / [SharpView](https://github.com/dmchell/SharpView) | PowerShell và .NET tool để thu thập thông tin AD, thay thế lệnh `net*`. Hữu ích cho Kerberoasting, ASREPRoasting. |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Vẽ sơ đồ mối quan hệ AD để lập kế hoạch tấn công. Cần [Neo4j](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors). |
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) | Trình thu thập dữ liệu AD cho BloodHound, xuất JSON để phân tích. |
| [BloodHound.py](https://github.com/fox-it/BloodHound.py) | Ingestor bằng Python sử dụng [Impacket](https://github.com/CoreSecurity/impacket). Chạy từ máy không gia nhập domain. |
| [Kerbrute](https://github.com/ropnop/kerbrute) | Công cụ Go kiểm tra xác thực Kerberos, brute-force, password spraying. |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Bộ công cụ Python tương tác với các giao thức mạng, nhiều script hỗ trợ AD. |
| [Responder](https://github.com/lgandx/Responder) | Poison các giao thức LLMNR, NBT-NS, MDNS. |
| [Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1) | PowerShell spoofing giống Responder. |
| [InveighZero](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh) | Phiên bản C# của Inveigh, có giao diện tương tác. |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | Enum AD qua RPC từ Linux (Samba suite). |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Công cụ đa năng cho enum và tấn công AD qua SMB, WMI, WinRM, MSSQL. |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Công cụ C# chuyên abuse Kerberos. |
| [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) | Tìm SPN liên kết user, hỗ trợ Kerberoasting. |
| [Hashcat](https://hashcat.net/hashcat/) | Công cụ crack mật khẩu mạnh mẽ. |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) | Công cụ enum thông tin từ Windows/Samba. |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | Bản cải tiến của enum4linux. |
| [ldapsearch](https://linux.die.net/man/1/ldapsearch) | Công cụ dòng lệnh truy vấn LDAP. |
| [windapsearch](https://github.com/ropnop/windapsearch) | Script Python enum AD bằng LDAP. |
| [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) | PowerShell tool thực hiện password spraying. |
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) | Dò và khai thác môi trường dùng LAPS. |
| [smbmap](https://github.com/ShawnDEvans/smbmap) | Enum chia sẻ SMB. |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) | Shell semi-interactive qua SMB. |
| [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) | Remote command execution qua WMI. |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Tìm credentials trong file share. |
| [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) | Dựng server SMB để truyền file. |
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/cc731241(v=ws.11)) | Quản lý SPN trên AD. |
| [Mimikatz](https://github.com/ParrotSec/mimikatz) | Trích xuất hash, vé Kerberos, PTH, mật khẩu. |
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) | Dump SAM và LSA secrets từ xa. |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm) | Shell WinRM tiện dụng trên máy Windows. |
| [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) | Kết nối và điều khiển MSSQL từ xa. |
| [noPac.py](https://github.com/Ridter/noPac) | Exploit CVE-2021-42278 + 42287 để lên DA. |
| [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) | Enum các RPC endpoint. |
| [CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py) | Exploit PrintNightmare. |
| [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) | Relay SMB với NTLM. |
| [PetitPotam.py](https://github.com/topotam/PetitPotam) | Tấn công qua EFSRPC để ép máy xác thực. |
| [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) | Tạo TGT từ certificate. |
| [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py) | Dùng TGT hiện tại để lấy PAC. |
| [adidnsdump](https://github.com/dirkjanm/adidnsdump) | Dump bản ghi DNS từ AD. |
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) | Trích xuất mật khẩu từ Group Policy Preferences. |
| [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) | Dò các user không cần pre-auth Kerberos. |
| [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py) | Bruteforce SID. |
| [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) | Tạo vé TGT/TGS tuỳ chỉnh. |
| [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) | Leo thang đặc quyền từ child domain. |
| [AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | Trình duyệt AD offline, so sánh snapshot. |
| [PingCastle](https://www.pingcastle.com/documentation/) | Kiểm toán bảo mật AD theo mô hình CMMI. |
| [Group3r](https://github.com/Group3r/Group3r) | Audit và tìm sai sót GPO trong AD. |
| [ADRecon](https://github.com/adrecon/ADRecon) | Thu thập và trình bày dữ liệu AD (xuất Excel). |
