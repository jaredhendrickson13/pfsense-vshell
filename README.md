# Introduction
pfSense vShell is a command line tool and Python module that enables users to remotely enter shell commands on a pfSense
host without enabling `sshd`. This allows administrators to automate installation of packages, enable `sshd`, and make other backend
changes out of the box.

# Installation
pfSense vShell requires Python3/Pip3 for installation<br>

To install:<br>
`pip install pfsense-vshell` 

To uninstall:<br>
`pip uninstall pfsense-vshell`

# Command Line

## Usage & Syntax
```
usage: pfsense-vshell [-h] --host HOST [--virtual_shell] [--command COMMAND] [--check_auth COMMAND] --username USERNAME --password PASSWORD [--scheme {http,https}] [--port PORT] [--timeout TIMEOUT] [--shell_timeout SHELL_TIMEOUT] [--no_verify] [--version] [--verbose]
```

| Command         | Shorthand | Required                              | Description                                                                                    | Example Usage           |
|-----------------|-----------|---------------------------------------|------------------------------------------------------------------------------------------------|-------------------------|
| --host          | -i        | Yes (except with --help or --version) | Set the IP or hostname of the remote pfSense host                                              | --host HOST             |
| --command       | -c        | No                                    | Run a single shell command                                                                     | --command COMMAND       |
| --virtual_shell | -s        | No                                    | Start a interactive virtual shell                                                              | --virtual_shell         |
| --help          | -h        | No                                    | Display the help page                                                                          | --help                  |
| --version       | -V        | No                                    | Display the current version                                                                    | --version               |
| --username      | -u        | Yes (except with --help or --version) | Set the username to login with                                                                 | --username USERNAME     |
| --password      | -p        | Yes (except with --help or --version) | Set the password to login with                                                                 | --password PASSWORD     |
| --port          | -P        | No                                    | Set the TCP port of pfSense's webConfigurator                                                  | --port PORT             |
| --scheme        | -w        | No                                    | Set the HTTP protocol scheme. `http` or `https`                                                | --scheme SCHEME         |
| --no_verify     | -k        | No                                    | Disable SSL certificate verification                                                           | --no_verify             |
| --timeout       | -t        | No                                    | Set the connection timeout value (in seconds)                                                  | --timeout TIMEOUT       |
| --shell_timeout | -z        | No                                    | Set the virtual shell session timeout value (in seconds). Only available with --virtual_shell. | --shell_timeout TIMEOUT |
| --verbose       | -v        | No                                    | Enable verbose logging                                                                         | --verbose               |

## Examples
Below are some examples of common use cases for pfsense-vshell:<br>

1: Run a single shell command (with inline authentication)
```shell script
$ pfsense-vshell --host 127.0.0.1 --command "cat /etc/version" --username admin --password pfsense
2.4.5-RELEASE
```
2: Start an interactive virtual shell session to run multiple commands
```shell script
$ pfsense-vshell --host 127.0.0.1 --virtual_shell --username admin --password pfsense
---Virtual shell established---
admin@127.0.0.1:/usr/local/www $ uname -a
FreeBSD pfSense.localdomain 11.3-STABLE FreeBSD 11.3-STABLE #236 21cbb70bbd1(RELENG_2_4_5): Tue Mar 24 15:26:53 EDT 2020#     root@buildbot1-nyi.netgate.com:/build/ce-crossbuild-245/obj/amd64/YNx4Qq3j/build/ce-crossbuild-245/sources/FreeBSD-src/sys/pfSense  amd64
admin@127.0.0.1:/usr/local/www $ exit
---Virtual shell terminated---
```
3: Run a single command to enable `sshd` on pfSense
```shell script
$ pfsense-vshell --host 127.0.0.1 --command "pfSsh.php playback enablesshd" --username admin --password pfsense
```

4: Run a single command to install a package on pfSense
```shell script
$ pfsense-vshell --host 127.0.0.1 --command "pkg install -y pfSense-pkg-nmap" --username admin --password pfsense
```

5: Display pfSense vShell version
```shell script
$ pfsense-vshell --version
pfsense-vshell v2.0.0
```

## Notes
- When using `--virtual_shell`, you may enter the command `history` to display commands executed since the virtual shell
session started.
- Interactive commands cannot be run within pfSense vShell, there is no way to add additional input after you have run 
your command. 
- Some older versions (pre-2.3) may not work properly. Always test functionality for running against production systems.
- By default, you are placed in the webConfigurator's web-root directory (/usr/local/www/). You cannot change directories.
Any file interaction will be relative to this directory if not absolute.
- By default, any command run within pfSense vShell has root access. There is no way to change this so be careful.
- Your pfSense user must have access to the Diagnostics > Command Prompt page within the webConfigurator.

# Python3 Module
After installing the package, the `pfsense_vshell` module will also be made available to your Python3 scripts.

## Classes
```
PFClient(host, username, password, port=443, scheme='https', timeout=30, verify=True)
:   Initializes the object at creation
    :param host: (string) the IP or hostname of the remote pfSense host
    :param username: (string) the pfSense username to authenticate as.
    :param password: (string) the password for the pfSense username.
    :param port: (int) the remote TCP port of pfSense's webConfigurator. Defaults to 443.
    :param scheme: (string) the HTTP scheme to use. http or https. Defaults to https.
    :param timeout: (int) the timeout value in seconds for HTTP requests. Defaults to 30.
    :param verify: (bool) true to enable certificate verification, false to disable. Defaults to true.

    ### Properties
    obj.host
    :   (string) the IP or hostname of the remote pfSense host
    
    obj.username
    :   (string) the pfSense username to authenticate as
    
    obj.password
    :   (string) the password for the pfSense username
    
    obj.port
    :   (int) the remote TCP port of pfSense's webConfigurator
    
    obj.scheme
    :   (string) the HTTP scheme to use
    
    obj.timeout
    :   (int) the timeout value in seconds for HTTP requests
    
    obj.verify
    :   (bool) certificate verification toggle
    
    obj.history
    :   (array) previous commands executed
    
    obj.log
    :   (array) logged events
    
    obj.last_request
    :   (object) the last request object used
    

    ### Static methods

    version()
    :   Provides the current version of pfsense vShell
        :return: (string) the current pfSense vShell version

    ### Methods

    authenticate(self)
    :   Attempts to authenticate using the objects current properties
        :return: (bool) true if authentication was successful, false if it wasn't

    get_csrf_token(self, uri)
    :   Retrieves the current CSRF token for a page
        :param uri: (string) the URI (e.g. index.php) to retrieve the CSRF token from
        :return: (string) the CSRF token

    has_dns_rebind_error(self, req=None)
    :   Checks if the objects host encounters a DNS rebind error when connecting
        :param req: (object) optionally provide an existing Response object created by the requests module
        :return: (bool) true if a DNS rebind error was found, false if it wasn't

    is_host_pfsense(self, req=None)
    :   Checks if the remote host is running pfSense. This is intended to protect clients from accidentally sending
        their login credentials to the wrong host as well as prevent hosts from spamming non-pfSense hosts.
        :param req: (object) optionally provide an existing Response object created by the requests module
        :return: (bool) true if the host is running pfSense, false if it is not

    request(self, uri, method='GET', data=None)
    :   Makes HTTP requests on behalf of our object
        :param uri: (string) the URI (e.g. /index.php) to request on the remote host
        :param method: (string) the HTTP method to use in the request (e.g. POST, GET)
        :param data: (dict) the request body data to send in the request
        :return: (object) the Response object created by the requests module

    run_command(self, cmd)
    :   Executes a shell command on the remote host using pfSense's diag_command.php page
        :param cmd: (string) a shell command to execute
        :return: (string) output of the shell command

    url(self)
    :   Formats a full URL with the objects current property values
        :return: (string) full URL of our object

PFError(code, message)
:   Error object used by the PFVShell class

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException
```

## Examples
```python
import pfsense_vshell

# Create our PFClient object
vshell = pfsense_vshell.PFClient("127.0.0.1", username="admin", password="password")

# Run command to install package on pfSense
vshell.run_command("pkg install -y pfSense-pkg-sudo")
```