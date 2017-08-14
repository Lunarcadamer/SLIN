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
