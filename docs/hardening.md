************************************
# Security Hardening Notes for Windows
************************************

### 1.Disable LLMNR and Netbios NS


LLMNR can cause man in the middle attacks and crediantial theft. Also mostly first thing checked in internal pentesting. Highly recommended to disable it.

If we make a bat file that will disable LLMNR and Netbios it should be like this

```sh
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0x0 /f
for /f %%i in ('REG Query "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"') do REG ADD %%i /v NetbiosOptions /t REG_DWORD /d 0x2 /f
```


### 2.Disable IPv6

IPv6 tunneling bypasses the security of your IPv4 router and hardware firewall. Also Windows hosts are vulnerable to router advertisement type DOS attacks if routerdiscovery is not disabled on the system.
Best option is to disable IPv6 on the windows hosts if not used. If you have an IPv6 router, then skip this section

```sh
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f
```


### 3.Set UAC To Highest(Always Notify)

User Account Control (UAC) is one of main components that protect our Windows Host from total take over or further infections. By default its "notify me only when applications make changes to my computer".
Upon an infection or exploitation this cause an attacker to make change on UAC without any notification and escalate privileges. As its seen by the system as user is making changes on windows settings which shouldn't trigger any notification.
For this reason, UAC should be changed to highest degree (Always Notify) unless you are facing some problem with non-UAC supported applications.

```sh
  REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0x1 /f
  REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0x2 /f
  REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 0x1 /f
```

### 3.SMB Disable Version 1
There is version 2 and version 3 used in most new systems. Its better to disable SMB version 1 and never allow vulnerabilities like Eternalblue 

```sh
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v DependOnService /t REG_MULTI_SZ /d bowser\0mrxsmb20\0nsi /f
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mrxsmb10" /v Start /t REG_DWORD /d 0x0 /f
  REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0x0 /f
```

### 4.Require SMB Security Signatures
Everybody knows pass the hash type attacks. You can protect your systems on a level by enabling SMB signing and even enforcing it. For SMB v2 RequireSecuritySignature parameter should be enough.

```sh
  REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0x1 /f
```

### 5. LSA Protection

Additional protection for the Local Security Authority is required to prevent code injection that could compromise credentials and dump current system credentials (For example Mimikatz, Metasploit hashdump). Best to achieve this is to start LSASS.exe process as protected process. In that case only system protected processes can reach the lsass.exe.

```sh
  REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0x1 /f
```

This can cause authentication problems with 3rd party applications that are not Microsoft signed. In that case and also for further forensic investigation. You may want to enable auditing for lsass.exe.

```sh
  REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 0x8 /f
```


### Windows Active Directory
### GPP Exploitation Detection

XML Permission Denied Checks
	Place a new xml file in SYSVOL & set Everyone:Deny.
	Audit Access Denied errors.