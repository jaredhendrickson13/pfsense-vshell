# Introduction
pfSense vShell is a command line tool that enables users to remotely enter shell commands without enabling `sshd`.
This allows administrators to automate installation of packages, enable `sshd`, and make other backend changes out of 
the box.

# Installation
pfSense vShell requires Python3/Pip3 for installation<br>

To install:<br>
`pip3 install pfsense-vshell` 

To uninstall:<br>
`pip3 uninstall pfsense-vshell`

# Examples
Below are some examples of common use cases for pfsense-vshell. Please note, authentication may be passed in via inline
argument (specify `-u` followed by your username, and `-p` followed by your password), or interactive prompt (if `-u`
or `-p` are not specified). Inline authentication allows commands to be scripted easily, whereas interactive 
authentication will secure password input and allow users to specify multiple commands (like an actually shell)<br>

1: Run a single shell command (with inline authentication)
```shell script
$ pfsense-vshell 127.0.0.1 --command "cat /etc/version" -u admin -p pfsense
2.4.5-RELEASE
```
2: Start an interactive virtual shell session to run multiple commands (with interactive authentication)
```shell script
$ pfsense-vshell 127.0.0.1 --virtual-shell
Please enter username: admin
Please enter password:
---Virtual shell established---
admin@127.0.0.1:/usr/local/www $ uname -a
FreeBSD pfSense.localdomain 11.3-STABLE FreeBSD 11.3-STABLE #236 21cbb70bbd1(RELENG_2_4_5): Tue Mar 24 15:26:53 EDT 2020#     root@buildbot1-nyi.netgate.com:/build/ce-crossbuild-245/obj/amd64/YNx4Qq3j/build/ce-crossbuild-245/sources/FreeBSD-src/sys/pfSense  amd64
admin@127.0.0.1:/usr/local/www $ exit
---Virtual shell terminated---
```
3: Run a single command to enable `sshd` on pfSense (with interactive password input)
```shell script
$ pfsense-vshell 127.0.0.1 --command "pfSsh.php playback enablesshd" -u admin
```

4: Run a single command to install a package on pfSense (with inline authentication)
```shell script
$ pfsense-vshell 127.0.0.1 --command "pkg install -y pfSense-pkg-nmap" -u admin -p pfsense
```

5: Display pfSense vShell version
```shell script
$ pfsense-vshell --version
pfsensevshell v0.0.1 Darwin/x86_64
```
# Restrictions
- Interactive commands cannot be run within pfSense vShell, there is no way to add additional input after you have run 
your command. If the command does not return a return code within 90 seconds the command will timeout.
- Some older versions (pre-2.3) may not work properly. Always test functionality for running against production systems.
- Virtual shell sessions will automatically close after 90 seconds of non-activity. The timeout timer will reset after
every command input.
- By default, you are placed in the webConfigurator's web-root directory (/usr/local/www/). You cannot change directories.
Any file interaction will be relative to this directory if not absolute.
- By default, any command run within pfSense vShell has root access. There is no way to change this so be careful.
- Your pfSense user must have access to the Diagnostics > Command Prompt page within the webConfigurator.


