# IMPORT MODULES #
import datetime
import getpass
import html
import platform
import socket
import sys
import requests  # Requires pip3 pkg requests
import urllib3  # Requires pip3 pkg urllib3


# Variables
req_session = requests.Session()  # Start our requests session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable urllib warnings


# CLASSES #
# PfaVar is a class of variables shared between different Python scripts
class PfaVar:
    v_tag = "1.0.0_1"    # Set the version tag, this should be the single source for version number
    software_version = "v" + v_tag + " " + platform.system() + "/" + platform.machine()    # Software version header
    local_user = getpass.getuser()  # Save our current user's username to a string
    local_hostname = socket.gethostname()  # Gets the hostname of the system running pfsense-vshell
    current_date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")  # Get the current date in a file supported format
    wc_protocol = "https"  # Assigns whether the script will use HTTP or HTTPS connections
    wc_protocol_port = 443 if wc_protocol == 'https' else 80  # If PfaVar.wc_protocol is set to https, assign a integer value to coincide

# FUNCTIONS #

# get_exit_message() takes an exit code and other parameters to determine what success or error message to print
def get_exit_message(ec, server, command, data1, data2):
    # Local Variables
    exit_message = ""    # Define our return value as empty string
    cmd_flg_len = 30   # Set the maximum length of our command flags to use in formatting table data
    global_dns_rebind_msg = "Error: DNS rebind detected. Ensure `" + server + "` is listed in System > Advanced > Alt. Hostnames"
    global_auth_err_msg = "Error: Authentication failed"
    global_platform_err_msg = "Error: `" + server + "` does not appear to be running pfSense"
    global_permission_err_msg = "Error: Unable to execute function. Your user may lack necessary permissions"
    # Define our ERROR/SUCCESS message dictionary
    ecd = {
        # Generic error message that don't occur during commands
        "generic" : {
            "invalid_arg" : "Error: Invalid argument. Unknown command `" + data1 + "`",
            "connect_err" : "Error: Failed connection to " + server + ":" + str(PfaVar.wc_protocol_port) + " via " + PfaVar.wc_protocol,
            "invalid_host" : "Error: Invalid hostname. Expected syntax: `pfsense-vshell <HOSTNAME or IP> <COMMAND> <ARGS>`",
            "timeout" : "Error: Connection timeout",
            "connection" : "Error: Connection dropped by remote host",
            "version" : "pfsense-vshell " + PfaVar.software_version,
            "syntax" : "pfsense-vshell <HOSTNAME or IP> <COMMAND> <ARGS>"
        },
        # Error/success messages for --check-auth flag
        "--check-auth": {
            "success": "Authentication successful",
            "fail": "Error: Authentication failed",
            "descr": structure_whitespace("  --check-auth",cmd_flg_len," ",True) + " : Test authentication credentials"
        },
        # Error/success messages for --version
        "--version": {
            "descr": structure_whitespace("  --version (-v)",cmd_flg_len," ",True) + " : Check the version of pfSense vShell"
        },
        # Error/success messages for --virtual-shell
        "--virtual-shell": {
            2: "Error: Unexpected response from command `" + data1 + "`",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --virtual-shell (-s)", cmd_flg_len, " ", True) + " : Start a virtual shell",
        },
        # Error/success messages for --command
        "--command": {
            2: "Error: Unexpected response from command `" + data1 + "`",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --command (-c)", cmd_flg_len, " ", True) + " : Run a single shell command",
        },
        # Error/success messages for --help
        "--help": {
            "descr": structure_whitespace("  --help (-h)", cmd_flg_len, " ", True) + " : Show help page",
        }
    }
    # Pull the requested message, return entire dictionary if "all" command is passed, otherwise just return the single values
    exit_message = ecd[command][ec] if command != "all" else ecd
    # Return our message
    return exit_message

# http_request() uses the requests module to make HTTP POST/GET requests
def http_request(url, data, headers, files, timeout, method):
    # Local Variables
    resp_dict = {}    # Initialize response dictionary to return our response values
    data = {} if type(data) != dict else data
    headers = {} if type(headers) != dict else headers
    files = {} if type(files) != dict else files
    no_resp_mode = True if timeout <= 5 else False    # Determine if user expects a response based on timeout value
    method_list = ['GET', 'POST']    # Set a list of supported HTTP methods
    # Check that our method is valid
    if method.upper() in method_list:
        # Process to run if a GET request was requested
        if method.upper() == "GET":
            get_timed_out = False    # Assign bool to track whether we received a timeout
            get_conn_err = False    # Assign a bool to track whether we received a connection error
            try:
                req = req_session.get(url, headers=headers, verify=False, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                get_timed_out = True
            except requests.exceptions.ConnectionError:
                get_conn_err = True
            # If our connection timed out AND our timeout value was greater than 5 seconds
            if get_timed_out and timeout > 5:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
            # If our connection returned an error
            if get_conn_err:
                print(get_exit_message("connection", "", "generic", "", ""))
                sys.exit(1)
        # Process to run if a POST request was requested
        elif method.upper() == "POST":
            post_timed_out = False  # Assign bool to track whether we received a timeout
            post_conn_err = False  # Assign a bool to track whether we received a connection error
            # Try to open the connection and gather data
            try:
                req = req_session.post(url, data=data, files=files, headers=headers, verify=False, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                post_timed_out = True
            except requests.exceptions.ConnectionError:
                post_conn_err = True
            # If our connection timed out AND our timeout value was greater than 5 seconds
            if post_timed_out and timeout > 5:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
            # If our connection returned an error
            if post_conn_err:
                print(get_exit_message("connection", "", "generic", "", ""))
                sys.exit(1)
        # Check if responseless mode is disabled
        if not no_resp_mode:
            # Populate our response dictionary with our response values
            resp_dict["text"] = req.text  # Save our HTML text data
            resp_dict["resp_code"] = req.status_code  # Save our response code
            resp_dict["req_url"] = url    # Save our requested URL
            resp_dict["resp_url"] = req.url    # Save the URL returned in our response
            resp_dict["resp_headers"] = req.headers  # Save our response headers
            resp_dict["method"] = method.upper()    # Save our HTTP method
            resp_dict['encoding'] = req.encoding    # Save our encode type
            resp_dict['cookies'] = req.cookies    # Save our encode type
        # Return our response dict
        return resp_dict
    # Return method error if method is invalid
    else:
        raise ValueError("invalid HTTP method `" + method + "`")


# structure_whitespace() takes a string and a length and adds whitespace to ensure that string matches that length
def structure_whitespace(string, length, char, strict_length):
    # Check that variables are correct type
    if type(string) is str and type(length) is int:
        # Check the string length
        if len(string) < length:
            # Loop until the str is the appropriate length
            while len(string) < length:
                string = string + char    # Add single whitespace
        # If strict_length is True, remove extra character length from longer strings
        if len(string) > length and strict_length:
            # Loop through through string length and remove anything after the max length
            rem_loop = 0    # Assign a loop index to track which character we are on
            rem_string = ""    # Assign variable to temporarily assign our characters to
            for c in string:
                # Check if we've reach our max length -3 (make room for ellipses)
                if rem_loop == length - 3:
                    rem_string = rem_string + "..."     # Add ellipses
                    string = rem_string    # Save rem_string to our return string
                    break
                # Add the character to our string and increase our index
                rem_string = rem_string + c
                rem_loop = rem_loop + 1
    # Return our structured string
    return string


# filter_input() sanitizes a string of special or otherwise malicious characters. Returns the formatted string.
def filter_input(stf):
    # Local Variables
    special_chars = [
        ",","~","!","@","#","$","%","^","&","*","(",")","+",
        "=","{","}","[","]","\\", "\"","\'",":",";","\'","?","/","<",">"
    ]
    # Check if input is string
    if isinstance(stf, str):
        # For each character in the list, replace the character with blank space
        for char in special_chars:
            stf = stf.replace(char,"")
    # Return filtered string
    return stf


# check_remote_port tests if a remote port is open. This function will return True if the connection was successful.
def check_remote_port(HOST,PORT):
    check_connect = None    # Initialize check_connect a variable to track connection statuses
    not_resolve = None     # Initialize not_resolve for use in DNS resolution errors
    port_open = False    # Assign boolean variable to return from this function
    port_test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Setup a socket for testing connections to a remote host and port
    port_test_sock.settimeout(0.5)    # Set the socket timeout time. This should be as low as possible to improve performance
    # Try to use the socket to connect to the remote port
    try:
        check_connect = port_test_sock.connect_ex((HOST,PORT))    # If the port test was successful, check_connect will be 0
        port_test_sock.close()    # Close the socket
    # If we could not connect, determine if it was a DNS issue and print error
    except socket.gaierror as sockErr:
        not_resolve = True
    # If the connection was established, return port_open as true. Otherwise false
    if check_connect == 0:
        port_open = True
    return port_open


# check_permissions() tasks an HTTP response and determines whether a permissions error was thrown
def check_permissions(http_resp):
    # Local Variables
    permit = False    # Default our return value to false
    no_user_page = "<a href=\"index.php?logout\">No page assigned to this user! Click here to logout.</a>"    # HTML error page when user does not have any permissions
    # Check if our user receives responses indicating permissions failed
    if no_user_page not in http_resp["text"] and http_resp["req_url"].split("?")[0] == http_resp["resp_url"].split("?")[0]:
        permit = True    # Return a true value if our response looks normal
    # Return our boolean
    return permit


# check_dns_rebind_error() checks if access to the webconfigurator is denied due to a DNS rebind error
def check_dns_rebind_error(url, req_obj):
    # Local Variables
    http_response = req_obj["text"] if req_obj is not None else http_request(url, {}, {}, {}, 45, "GET")["text"]    # Get the HTTP response of the URL
    rebind_error = "Potential DNS Rebind attack detected"    # Assigns the error string to look for when DNS rebind error occurs
    rebind_found = False    # Assigns a boolean to track whether a rebind error was found. This is our return value
    # Check the HTTP response code for error message
    if rebind_error in http_response:
        rebind_found = True    # If the the HTTP response contains the error message, return true
    # Return our boolean
    return rebind_found


# check_auth() runs a basic authentication check. If the authentication is successful a true value is returned
def check_auth(server, user, key):
    # Local Variables
    auth_success = False    # Set the default return value to false
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)   # Assign our base URL
    auth_check_data = {"__csrf_magic": get_csrf_token(url + "/index.php", "GET"), "usernamefld": user, "passwordfld": key, "login": "Sign In"}    # Define a dictionary for our login POST data
    pre_auth_check = http_request(url + "/index.php", {}, {}, {}, 45, "GET")
    # Check that we're not already signed
    if not "class=\"fa fa-sign-out\"" in pre_auth_check["text"]:
        # Complete authentication
        auth_check = http_request(url + "/index.php", auth_check_data, {}, {}, 45, "POST")
        auth_success = True if not "Username or Password incorrect" in auth_check["text"] and "class=\"fa fa-sign-out\"" in auth_check["text"] else auth_success    # Return false if login failed
    # Else return true because we are already signed in
    else:
        auth_success = True
    return auth_success


# check_errors() consolidates all error check functions into one
def check_errors(server, user, key, priv_list):
    # Local variables
    ec = 2    # Init our error code to 2
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    get_base = http_request(url, None, None, None, 45, "GET")    # Get our base URL to check for errors
    # Submit our intitial request and check for errors
    ec = 10 if check_dns_rebind_error(url, get_base) else ec    # Return exit code 10 if dns rebind error found
    ec = 6 if not validate_platform(url, get_base) else ec    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ec == 2:
        ec = 3 if not check_auth(server, user, key) else ec    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if ec == 2:
        # Check that we had permissions for each page in priv_list, if we do not, break and return error 15
        for p in priv_list:
            priv_check = http_request(url + "/" + p, None, None, None, 45, "GET")
            if not check_permissions(priv_check):
                ec = 15
                break
    # Return our exit code
    return ec


# get_csrf_token() makes an initial connection to pfSense to retrieve the CSRF token. This supports both GET and POST requests
def get_csrf_token(url, type_var):
        # Local Variables
        csrf_token_length = 55  # Set the expected token length of the csrf token
        csrf_response = http_request(url, None, {}, {}, 45, type_var)
        # Parse CSRF token and conditionalize return value
        if "sid:" in csrf_response['text']:
            csrf_parsed = "sid:" + csrf_response['text'].split("sid:")[1].split(";")[0].replace(" ", "").replace("\n", "").replace("\"", "")
            csrf_token = csrf_parsed if len(csrf_parsed) is csrf_token_length else ""    # Assign the csrf_token to the parsed value if the expected string length is found
        # If we could not find a CSRF token
        else:
            csrf_token = ""    # Assign blank CSRF token as none was found
        return csrf_token    # Return our token


# validate_platform()
def validate_platform(url,req_obj):
    # Local variables
    html_str = req_obj["text"] if req_obj is not None else http_request(url, {}, {}, {}, 45, "GET")["text"]    # Get our HTML data
    platform_confidence = 0    # Assign a integer confidence value
    # List of platform dependent key words to check for
    check_items = [
        "pfSense", "pfsense.org", "Login to pfSense", "pfsense-logo", "pfSenseHelpers",
        "netgate.com", "__csrf_magic", "ESF", "Netgate", "Rubicon Communications, LLC",
        "Electric Sheep Fencing LLC", "https://pfsense.org/license"
    ]
    # Loop through our list and add up a confidence score
    for ci in check_items:
        # Check if our keyword is in the HTML string, if so add 10 to our confidence value
        platform_confidence = platform_confidence + 10 if ci in html_str else platform_confidence
    # Determine whether our confidence score is high enough to allow requests
    platform_confirm = True if platform_confidence > 50 else False
    # Return our bool
    return platform_confirm


# print_help_page() prints the help page
def print_help_page():
    print("pfsense-vshell " + PfaVar.software_version)
    print("SYNTAX:")
    print("  " + get_exit_message("syntax", "", "generic", "", ""))
    flag_descrs = ""  # Initialize our flag description help string
    flag_dict = get_exit_message("", "", "all", "", "")  # Pull our descr dictionary
    # Loop through our flag descriptions and save them to a string
    for key, value in flag_dict.items():
        # Only perform this on dict keys with -- flags
        if key.startswith("--"):
            flag_descrs = flag_descrs + value["descr"] + "\n"  # Format our return string
    print("COMMANDS:")
    print(flag_descrs.rstrip("/"))

# parse_url() allows a URL with custom protocol and port to be used
def parse_url(url):
    # Local Variables
    pfsense_server = url.replace("https://", "")  # Assign the server value to the first_arg (filtered)
    # Check if user requests HTTPS override
    if pfsense_server.lower().startswith("http://"):
        pfsense_server = pfsense_server.replace("http://", "")  # Replace the http:// protocol from the servername
        PfaVar.wc_protocol = "http"  # Reassign our webconfigurator protocol
        PfaVar.wc_protocol_port = 80  # Assign webconfigurator port to HTTP (80)
    # Check if user requests non-standard UI port
    if ":" in pfsense_server:
        non_std_port = pfsense_server.split(":")[1]  # Assign the value after our colon to a variable
        non_std_port_int = int(non_std_port) if non_std_port.isdigit() else 999999  # Assign a integer value of our port variable, if it is not a number save out of range
        PfaVar.wc_protocol_port = non_std_port_int if 1 <= non_std_port_int <= 65535 else PfaVar.wc_protocol_port  # Change our webUI port specification if it is a valid number
        pfsense_server = pfsense_server.replace(":" + non_std_port, "")  # Remove our port specification from our servername string
    return pfsense_server


# get_shell_output() executes a shell command in diag_command.php and returns it's output
def get_shell_output(server, user, key, cmd):
    # Local variables
    shell_out = {"ec": 2, "shell_output" : ""}    # Create a dictionary to track our return code and our shell cmd output
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our initial request and check for errors
    shell_out["ec"] = 10 if check_dns_rebind_error(url, None) else shell_out["ec"]    # Return exit code 10 if dns rebind error found
    shell_out["ec"] = 6 if not validate_platform(url, None) else shell_out["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if shell_out["ec"] == 2:
        shell_out["ec"] = 3 if not check_auth(server, user, key) else shell_out["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if shell_out["ec"] == 2:
        # Check that we had permissions for this page
        get_shell_data = http_request(url + "/diag_arp.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(get_shell_data):
            # Create our POST data dictionary and run our POST request
            shell_cmd_post_data = {"__csrf_magic": get_csrf_token(url + "/diag_command.php", "GET"), "txtCommand": cmd, "submit": "EXEC"}
            shell_cmd_post = http_request(url + "/diag_command.php", shell_cmd_post_data, {}, {}, 90, "POST")
            # Check that our output <pre> tags exist
            if "<pre>" in shell_cmd_post["text"]:
                shell_out["shell_output"] = html.unescape(shell_cmd_post["text"].split("<pre>")[1].split("</pre>")[0])    # Update our shell output value
                shell_out["ec"] = 0    # Return exit code 0 (success)
        # If we did not have permission, return exit code 15 (permission denied)
        else:
            shell_out["ec"] = 15
    # Return our data dictionary
    return shell_out