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
