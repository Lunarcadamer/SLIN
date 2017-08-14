# SLIN Cheatsheet

## Topic 0 (Linux Basics)

### Check hostname
`hostnamectl`  
`hostnamectl set-hostname <your hostname>`  

### Users
`useradd <username>`  
`passwd <username>`  

### Groups
`groupadd <groupname>`  
`usermod -aG <groupname> <username>` -aG = append to group  
`chgrp <groupname> <filename>` To change group owner of file  

## Topic 1 (Using Cent0S)

### SSH Configurations
`netstat -tunap | grep <service name>` Use netstat to check which port a service is running on  
SSH service file `/etc/ssh/sshd_config`  
`semanage port -a -t ssh_port_t -p tcp 8222` Allow SSH to listen on port 8222  

### SCP and SFTP
`scp <serverIP>:<file> <destination>`
`get <file> <save as>` Using SFTP to download a file

### Network Configuration
`nmcli` Stands for Network Manager's Command Line Interface  
`nmcli device` View network devices  
`nmcli connection modify eno16777736 ipv4.addresses “192.168.137.30/24 192.168.137.2” ipv4.dns 192.168.137.2` Setting a static IP address  
`nmcli connection modify eno16777736 ipv4.method manual` Specify using a IP address  
`nmcli device disconnect/connect eno16777736` Disconnect and connect for changes to take effect  
`/etc/sysconfig/network-scripts/ifcfg-<name of network interface>` Network settings file  

### Kernal Parameters
`sysctl -a` View list of available kernal parameters  
`sysctl -w net.ipv4.icmp_echo_ignore_all=1` Set kernal to ignore ping packets  
`sysctl -p` Load settings from /etc/sysctl.conf  

### Prevent Root Login
`visudo` To modify sudoer file  
`<username> ALL=ALL` To enable root previleges  
`root:x:0:0:root:/root:/sbin/nologin` Add '/sbin/nologin' in /etc/passwd to enable non-interactive shell  
`/bin/bash` For interactive shell  

### Chroot
`setsebool -P ftp_home_dir on` To allow users to access their home directories  
Editing `/etc/vsftp.conf`  
`chroot_list_enable=YES`  
`chroot_list_file=/etc/vsftpd/chroot_list`  
`allow_writeable_chroot=YES`  

### SELinux
`getenforce`  
`setenforce 0` Permissive mode  
`setenforce 1` Enforcing mode  
`getsebool -a | less` View SELinux booleans  
Edit `/etc/selinux/config` to set mode on bootup  
`ls -lZ <filename>` View SELinux file contexts  
`chcon -t shadow_t <filename>` To screw up file context  
`restorecon <filename>` To reset file context  

### VSFTPD & SELinux
`mkdir /var/ftp/incoming`  
`chgrp ftp /var/ftp/incoming`  
`chmod 730 /var/ftp/incoming`  
Uncomment `anon_upload_enable=YES` to allow anonymous uploads  

## Topic 2 (Web Servers)

### Apache Configuration
`/etc/httpd/conf/httpd.conf` Apache Config file  
`<Directory /var/www/html/books>
    Options -Indexes
 </Directory>  
`
Turning off Indexes  

### Virtual Hosts
`<VirtualHost your_server_ip:80>
    ServerName www.flowers.com
    DocumentRoot /var/www/flowers
    ErrorLog /var/log/httpd/flowers-error_log
    CustomLog /var/log/httpd/flowers-access_log combined
 </VirtualHost>`    

### CGI Scripts
`chcon –t httpd_sys_script_exec_t /var/www/fruits-cgi-bin` Setting file context  
`#!/usr/bin/perl
print “Content-type: text/html\n\n”;
print “Hello World”;
`  
`chmod 755 /var/www/fruits-cgi-bin/test.pl`  

### User Authentication (Section 8)
`htpasswd –cm /etc/httpd/conf/flowers-users bob`  
`htpasswd –m /etc/httpd/conf/flowers-users alice` -c option not used, only first entry requires it  

### Tomcat (Section 12)
`/var/lib/tomcat/webapps` Tomcat directory  

### nginx (Section 14)
Create the text file /usr/lib/systemd/system/nginx.service and enter the following contents.  
`[Unit]
Description=The NGINX HTTP server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/usr/local/nginx/logs/nginx.pid
ExecStartPre=/usr/local/nginx/sbin/nginx -t
ExecStart=/usr/local/nginx/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target`  

`/usr/local/nginx/sbin/nginx –s stop` Before you use the systemctl commands to start nginx, make sure nginx is not running already from the last exercise.  

## Topic 3 (File Systems)

### Partition Creation
`fdisk -l` View existing partitions  
To create a new partition on the hard disk, type "fdisk /dev/sda".  
* In fdisk, type 'm' to view the available options.  
* Type “p” to list the existing partitions on the hard disk.  
* To create a new partition, type 'n'.  
* Type 'p' to create a third primary partition. (as you already have 2 partitions)  
* Type “3” for Partition number 3.  
* Press enter to accept the default starting sector.  
* Type “+100M” to create a 100MB partition.  
* Type 'p' to list the partition info. Note your third partition and its device name (/dev/sda3). Also note its ID, which is 83 for Linux.  Type 'w' to write changes to disk and exit fdisk  

### Formating Partition & Mount on boot (Section 1b)
`/etc/fstab` Modify for mounting during boot  

### Mounting directories on server (Section 2)
Check nfs-server service  
`mkdir -p /exports/data`  
`chmod 777 /exports/data`  
Edit /etc/exports, add line: `/exports/data     <clientIP>(ro,sync)`  
`exportfs -r` Re-export entries in /etc/exports  
`exportfs -v` Checking exports  

### Mounting directories on client (Section 3)
`mount <serverIP>:/exports/data /mount/data -o rw`  

### Export options (Section 4)
Edit /etc/exports on server, add line `/exports/data		<clientIP>(rw,root_squash,sync)`  

Note that files created by root over the NFS share are owned by nfsnobody. This is because by default, directories are exported with the root_squash option. The user root is mapped to user nfsnobody when accessing the exported directory.  

### Linux File Permissions and NFS (Section 5)
`mkdir /exports/data/student`  
`chown student.student /exports/data/student`  
`chmod 755 /exports/data/student`  

### Viewing exported directories by mounting pseudo-root (Section 6)
On server: Create another directory /exports2/mydata.  
`mkdir –p /exports2/mydata`  
Create some files in /exports2/mydata.  
Edit /etc/exports and add the following line.  
`/exports2/mydata		*(ro,sync)`  
Run exportfs with -r option to re-export the entries in /etc/exports.  
`exportfs -r`  
  
On client: Run the following command to mount the pseudo-root of the server to /mount.  
`mount serverIP:/ /mount`  
Do a ls of /mount to find out what has been exported from the server.  
`ls /mount`  
To unmount the directory  
`umount /mount`  

### Mount on bootup with /etc/fstab (Section 7)
On client: Append the following line in /etc/fstab so that the /mount/data will be mounted automatically upon every bootup.  
`serverIP:/exports/data	  /mount/data    nfs   defaults   0 0`  
Restart the client or run the following command to mount the /mount/data.  
`mount /mount/data`  
Check the contents of /mount/data to see if the server’s exported directory has been mounted.  
`ls /mount/data`  
`When you have completed the test, you can comment out the line that you just added to /etc/fstab so that it would not be automatically the next time you start your Linux client.`  

## Topic 4 (Network and Service Access Controls)

### Firewall commands
`firewall-cmd –-get-zones` Lists the firewall zones  
`firewall-cmd –-list-all-zones` Lists the firewall zones  
`firewall-cmd –-get–default-zone` View the default zone  
`firewall-cmd –-list-services` List services that are currently allowed  
`firewall-cmd --permanent --zone=public --remove-service=telnet` Permanently remove telnet from public zone  
`firewall-cmd --reload` Reloading the fire wall  
`firewall-cmd --permanent --zone=public --add-rich-rule=‘rule family=ipv4 service name=ftp source address=192.168.94.0/24 accept’` How to add a rich rule  


### Firewall files
`/etc/firewalld/zones/public.xml`  

## Topic 5 (Samba)

### Creating Samba Share
`yum install samba` Install Samba  
`yum install samba-client` Install Samba Client

`systemctl start smb` Start Samba service  
`systemctl enable smb` Enable Samba service

Samba configuration in /etc/samba/smb.conf  
Adding a samba share called "myshare"
`[myshare]  
comment = My Samba Share  
path = /samba_share (replace with folder to share)  
guest ok = yes/no  
browsable = yes/no`

`smbpasswd -a alvin` Set password for user "alvin"

### Browsing Samba Shares from Client
`smbclient -L <serverIP>` View Samba shares on the server

### Accessing anonymous Samba Shares from Client
`smbclient //<serverIP>/<Samba Share Name>`  
`smbclient //192.168.137.69/myshare` Example

Use `help` command to view avaliable commands

If there is an error when using `ls`, it could be due to SELinux settings.  
`setenforce 0` Turn off SELinux on server and retry the command  
`chcon -Rt samba_share_t /samba_share` If its due to SELinux, change the shared directory context  
`setenforce 1` Turn on SELinux when done

`get <filename>` Download shared file

`quit` to exit from Samba client

### Authenticating Users to access Samba Shares
Edit /etc/samba/smb.conf and remove "guest ok = yes"

`smbclient //<serverIP>/<sharedFolder> -U <username>` Logging in as a user, enter password when prompted

### Uploading files to Samba Share
`put <filename>` to upload files to the Samba Share, by default not allowed

Edit /etc/samba/smb.conf  
`write list = <username>` Add this line to specify which users can write to the Samba share

From Windows System, go to Start, Run.  
`\\<serverIP>\<sharedFolder>` into the Run window, a login prompt should appear

### Mounting Samba Share automatically upon bootup
`yum install cifs-utils` Common Internet File System (CIFS) for mounting  
`mkdir /sambadata` Create a mount point, in this case "/sambadata"

Edit /etc/fstab  
`//<serverIP>/<sharedFolder>    /<mountPoint>   cifs    credentials=/etc/sambauser 0 0`  
`//serverIP/myshare             /sambadata      cifs    credentials=/etc/sambauser 0 0` Example

Create a new file /etc/sambauser  
Add login credentials  
`user=alvin  
pass=alvinpassword`

Secure the credential files  
`chmod 600 /etc/sambauser`

### Accessing Home Directories through Samba
Edit /etc/samba/smb.conf  
`[homes]  
comment = Home Directories  
browsable = no  
writable = yes`

Turn on SELinux Booleans to allow access to home directories  
`setsebool -P samba_enable_home_dirs on`

## Topic 6 (Securing Data)

### Random Number Generation
`hexdump /dev/random` Move mouse to generate random bytes  
`hexdump /dev/urandom` No need to move mouse, but not truly random

`openssl rand -base64 8` Using OpenSSL to generate 8 random bytes in Base64  
`openssl rand 8` 8 random bytes, but not necessarily printable

### One Way Hashes
`md5sum <file> > <outputFile>` Creating a file with the md5 fingerprint of another file

### Working with multiple fingerprints
`sha1sum /etc/pam.d/* > /root/pam_sign.sha1` Creating SHA1 fingerprints of all files in /etc/pam.d  
`sha1sum --check /root/pam_sign.sha1` To compare the signatures to see if there was any modification

### Symmetric Encryption
`openssl des3 -base64 -in <plaintextFile> -out <encryptedFile>` Using Triple-DES to encrypt a file, there will be a prompt for a password  
`openssl des3 -d -base64 -in <encryptedFile>` Decrypting file, provide the correct password to decrypt

### Asymmetric Encryption
**IMPORTANT: Login at the GUI as the users to generate the keys, don't just `su`**  
`gpg --gen-key` to generate keys  
`gpg --list-keys` to view public keys  
`gpg --list-secret-keys` to view private keys  

`gpg -a --export AliceLim > /tmp/alice_pubkey` Exporting public key of AliceLim  
`gpg --import /tmp/alice_pubkey` Importing Alice's public key

`gpg --recipient AliceLim -a -o /tmp/ciphertext -e /tmp/plaintext` Encrypting a message for Alice  
`gpg -o alicetext -a -d /tmp/ciphertext` Decrypting the message, remember to login as Alice

### Digital Signatures (Section 6)
`gpg --recipient BobTan -a --sign -o /tmp/signcipher -e alicetext` Encrypting alicetext and signing it with alice's private key  
`gpg -o bobtext -a -d /tmp/signcipher` Decrypting and verifying "signcipher" file

### Creating a self-sign cert for Apache web server
Start the Apache web server 'systemctl start httpd'

As root, go to /etc/pki/tls/certs  
`make httpd.key` to generate a private key for Apache  
`make httpd.crt` to generate a self-signed certificate

`mv /etc/pki/tls/certs/httpd.key /etc/pki/tls/private` Moving the private key to the private directory

`yum install mod_ssl` Install the SSL module for Apache if not yet installed

Edit /etc/httpd/conf.d/ssl.conf
`SSLCertificateFile /etc/pki/tls/certs/httpd.crt`  
`SSLCertificateKeyFile /etc/pki/tls/private/httpd.key`

Restart once modified

### Setting up a private Certificate Authority (Section 8)
Check for directories /etc/pki/CA/private (Stores private key of CA) and /etc/pki/CA/certs (stores certs)  
Create them if they do not exist

`chmod 700 /etc/pki/CA/private` Ensure the directory is accessible only to root

Edit /etc/pki/tls/openssl.cnf, add the following lines:  
`dir = /etc/pki/CA`  
`certificate = $dir/certs/slin-ca.crt`  
`private_key = $dir/private/slin-ca.key`

Create two files to be used by the private CA  
`touch /etc/pki/CA/index.txt`  
`echo 01 > /etc/pki/CA/serial`

Generate a 2048-bit private for the private CA, besure to be in /etc/pki/CA  
`openssl genrsa -des3 2048 > private/slin-ca.key`  
`chmod 600 /etc/pki/CA/private/slin-ca.key` Ensure private key is only accessible by root  
Run the following command to generate a self-signed cert for the private CA  
`openssl req -new -x509 -days 365 -key private/slin-ca.key > certs/slin-ca.crt`

`ls /etc/pki/CA/certs` to check that the cert is created

Copy the cert to the webserver  
`mkdir /var/www/html/pub` 
`cp /etc/pki/CA/certs/slin-ca.crt /var/www/html/pub`

### Sign Apache Web Server Certificate using private CA (Section 9)
Change directory to /etc/pki/tls

Generate new private key for webserver  
`openssl genrsa 1024 > private/httpd.key` Remember the passphrase  
`chmod 600 private/httpd.key`  
`openssl req -new -key private/httpd.key -out certs/httpd.csr` Generate the certificate signing request

Use the CA private key to sign the CSR, passphrase for the key will be required
`openssl ca -in certs/httpd.csr -out certs/httpd.cert`

Edit /etc/httpd/conf.d/ssl.conf, modify these lines if they are different  
`SSLCertificateFile /etc/pki/tls/certs/httpd.crt`  
`SSLCertificateKeyFile /etc/pki/tls/private/httpd.key`

Restart the Apache webserver

### SSH with key-based authentication (Section 10)
**On Client**  
As user student, generate a pair of private/public RSA keys for SSH. Accept the default values and set a passphrase.  
`ssh-keygen -t rsa` 
Create the directory /home/student/.ssh  
`chmod 700 .ssh`

Copy the public key from the client to the server /home/student/.ssh/authorized_keys  
`scp /home/student/.ssh/id_rsa.pub serverIP:/home/student/.ssh/authorized_keys`

As user student, ensure file /home/student/.ssh/authorized_keys is only accessible by the owner  
`chmod 600 authorized_keys`

### SSH Agent (Section 11)
**On Client**  
As user student, start SSH Agent  
`eval $(ssh-agent -s)`

Load keys to the SSH agent. (this step not necessary if user student already logged in at GUI)  
`ssh-add`

`ssh <serverIP>` Now no passphrase has to be entered.

### Virtual Network Computing through SSH Tunnel (Section 12)
`yum install vnc-server` to install the VNC server

Make a copy of the vncserver config file (run the command in a single line).  
`cp /lib/systemd/system/vncserver@.service  /etc/systemd/system/vncserver@.service`

Edit /etc/systemd/system/vncserver@.service and modify the following line to replace <USER> with student to connect.  
`ExecStart=/sbin/runuser -l <USER> -c "/usr/bin/vncserver %i" PIDFile=/home/<USER>/.vnc/%H%i.pid`

Set VNC password
`vncpasswd`

Restart the service  
`systemctl daemon-reload`  
`systemctl start vncserver@:1`  

`netstat -tunap` To check for a listening port in the range of 5900 to 5905.  
Remember to adjust the firewall to allow connections to the VNC Server

**On Client**  
`yum install vnc`  
`vncviewer <serverIP>:1`  

To use SSH  
`vncviewer -via <serverIP> localhost:1`

### Using SSH Tunnel to do Local Port Forwarding (Section 13)

Refer to tutorial 6, section 13

## Topic 7 (System Monitoring)

## Mock Test Paper for Reference
Suggested solutions for SLIN Revision Questions for End of Semester Practical Test

Important : Know how to access the various man pages for more help. Apache web server has its Apache manual website that can be installed.

1.	Using GUI : Click on the Network icon in top right corner, and go to Network Settings. For Wired Connection, click on the Gear icon in bottom right corner. In the left hand pane, select IPv4. Select Manual and set the IP address, subnet mask, gateway and the DNS Server.
2.	
Alternatively, edit the network config file /etc/sysconfig/network-scripts/ifcfg-eno16777736 and specify the BOOTPROTO, IPADDR, NETMASK, GATEWAY and DNS1.

You may need to restart the network for changes to take effect  
`systemctl status network`


3.	To create users and set their passwords

`useradd tan`  
`useradd wong`  
`useradd lee`  
`passwd tan (set the password to "password")`  
`passwd wong`  
`passwd lee`  


4.	Groups  
(i)	To create group  
`groupadd staff`

(ii)	To add users as secondary members of a group  
`usermod -aG staff tan`  
`usermod -aG staff wong`  


5.	SELinux  
Edit /etc/selinux/config and set the following :  
`SELINUX=enforcing`  



6.	Telnet Service  
(i)	Install xinetd and telnet-server and make xinetd start automatically upon next bootup  
`yum install xinetd`  
`yum install telnet-server`	not yum install telnet (this is telnet client)  
`chkconfig xinetd on`  

(ii)	Enable telnet-server to be started when there is a client request:  
`chkconfig telnet on`

(iii)	To configure telnet service to be available only to certain clients, edit /etc/xinetd.d/telnet and add in the following line:  
`only_from   = 192.168.0.0/16`

(iv)	To start xinetd now:  
`service xinetd start`


7.	Symmetric Encryption  
(i)	Create the file /tmp/myfile using any editor

(ii)	Encrypt the file /tmp/myfile with Triple-DES, using “hello” as the encryption key and store the encrypted output to /tmp/encrypted
`openssl des3 –in /tmp/myfile –out /tmp/encrypted`  
(Enter “hello” when asked for encrypted password)

(iii)	Decrypt the file /tmp/encrypted with Triple-DES, using “hello” as the encryption key and store the decrypted output to /tmp/decrypted
`openssl des3 –d –in /tmp/encrypted –out /tmp/decrypted`  
(Enter “hello” when asked for encrypted password)

(iv)	Check that /tmp/decrypted contains the original string “Good morning to all!”



8.	Asymmetric Encryption
(i)	As user tan, do the following to generate a pair of private and public keys :  
Login to the GUI as user tan.  
`gpg --gen-key (choose the default options and enter “JohnTan” as the Real name.`

To check that the keys have been created, run the following commands to list out the private and public key for JohnTan  
`gpg --list-secret-keys`  
`gpg --list-keys`  

(ii)	Create the file /home/tan/tanfile using any editor.

(iii)	Create a detached signature. The signature will be stored in the same directory as either tanfile.asc or tanfile.sig  
`gpg --detach-sign –a /home/tan/tanfile`

(iv)	Verify the detached signature. You should see “Good signature”  
`gpg --verify /home/tan/tanfile.asc`  

(v)	Export tan’s public key into a file  
`gpg --export –a > /tmp/tan_publickey`

(vi)	As user wong, import tan’s public key from a file  
`gpg --import –a /tmp/tan_publickey`

To check that the public key has been imported, as user wong, run the following command to list out the public key for JohnTan  
`gpg --list-keys`

(vii)	Create the file /tmp/file_for_tan using any editor.

(viii)	Encrypt the file /tmp/file_for_tan with tan’s public key. The encrypted output is sent to the file /tmp/encrypted_file_for_tan  
`gpg –-recipient JohnTan –a –o /tmp/encrypted_file_for_tan –e /tmp/file_for_tan`

To check that the file has been encrypted properly, as user tan, run the following command to decrypt the file  
`gpg –a -d /tmp/encrypted_file_for_tan`  

	

9.	Mail Service  
(i)	To install postfix (if it is not installed yet) and make it start automatically upon next bootup  
`yum install postfix`  
`chkconfig postfix on`  

(ii)	Make postfix listen on all network interfaces. Edit /etc/postfix/main.cf and change the inet_interfaces parameter:  
`inet_interfaces = all`

(iii)	To relay emails from clients in the 192.168.0.0/16 subnet, edit /etc/postfix/main.cf and change the mynetworks parameter:  
`mynetworks = 192.168.0.0/16`

(iv)	To receive emails for the domain, edit /etc/postfix/main.cf and change the mydestination parameter:  
`mydestination = singpoly.sg`

(v)	To create a mail alias, edit /etc/aliases and add the following line:  
`register:     tan`

(vi)	After making changes to the mail configuration, restart the service :  
`service postfix restart`



10.	System Logging  
(i)	Edit /etc/rsyslog.conf and add the following lines (some lines may already exist):  
`authpriv.*		/var/log/secure`  
`authpriv.error	/var/log/secureerr`  
`*.error			@192.168.9.9`

(ii)	Restart the rsyslog service  
`service rsyslog restart`



11.	Web Service  
(i)	To install the Web Service and make it start automatically upon next bootup :  
`yum install httpd`  
`chkconfig httpd on`  

(ii)	Check the value of DocumentRoot in /etc/httpd/conf/httpd.conf, This will be the directory where the Apache Web Server will look for the web pages. By default it is set to /var/www/html  
`DocumentRoot /var/www/html`

(iii)	To create index.html, create and edit the file  /var/www/html/index.html, and add the following line:  
`This is my school.`

(iv)	Start the Web service now:  
`service httpd start`





12.	Samba Service
(i)	To install the Samba Service and make it start automatically upon next bootup :  
`yum install samba`  
`chkconfig smb on`  

(ii)	Create the directory /mysamba and set the SELinux file context:  
`mkdir /mysamba`
`chcon –Rt samba_share_t /mysamba`  

(iii)	Edit /etc/samba/smb.conf and add the following lines:  
`[myfiles]`  
`path=/mysamba`  
`read only = yes`  
`guest ok = yes`  



13.	 Firewall

Note : You can also use the GUI to set the firewall. Make sure you are configuring permanent rules!

(i)Check that the firewall will be activated (enabled) upon bootup  
`systemctl status firewalld`

(ii)Add rich rule to firewall to allow incoming traffic from 192.168.0.0/16 to Web Server in the default public zone  
`firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 port port=80 protocol=tcp source address=192.168.0.0/16 accept'`

(iii)Add rich rule to firewall to allow incoming traffic from 192.168.0.0/16 to Telnet Server in the default public zone  
`firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 port port=23 protocol=tcp source address=192.168.0.0/16 accept'`

(iv)Add rich rule to firewall to allow incoming traffic from 192.168.0.0/16 to SMTP Server in the default public zone  
`firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 port port=25 protocol=tcp source address=192.168.0.0/16 accept'`

(v)Add rich rule to firewall to allow incoming traffic from 192.168.0.0/16 to Samba Server in the default public zone  
`firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 port port=445 protocol=tcp source address=192.168.0.0/16 accept'`

(vi)Check the config file if there are any other services already allowed and remove them.  
cat /etc/firewalld/zones/public.xml
