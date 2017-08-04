@echo off
::Disable LLMNR and Netbios NS
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0x0 /f
for /f %%i in ('REG Query "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"') do REG ADD %%i /v NetbiosOptions /t REG_DWORD /d 0x2 /f

::Disable IPv6
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f

::Set UAC To Highest(Always Notify)
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 0x1 /f

::SMB Disable Version 1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v DependOnService /t REG_MULTI_SZ /d bowser\0mrxsmb20\0nsi /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\mrxsmb10" /v Start /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0x0 /f

::Require SMB Security Signatures
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0x1 /f

::LSA Protection
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0x1 /f

::LSA Audit
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 0x8 /f