# SLIN Cheatsheet

## Topic 0

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

## Topic 1

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
 
