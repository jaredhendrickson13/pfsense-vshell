# Copyright 2022 Jared Hendrickson
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
"""Defines the client object used to establish virtual pfSense shell connections."""
__version__ = "2.0.4"

import datetime
import html

import requests
import urllib3


class PFClient:
    """Client object that facilitates controlling the virtual shell."""
    # Allow current number of instance attributes, they are needed to allow configurable connections
    # pylint: disable=too-many-instance-attributes

    def __init__(self, host, username, password, port=443, scheme="https", timeout=30, verify=True):
        """
        Initializes the object at creation
        :param host: (string) the IP or hostname of the remote pfSense host
        :param username: (string) the pfSense username to authenticate as.
        :param password: (string) the password for the pfSense username.
        :param port: (int) the remote TCP port of pfSense's webConfigurator. Defaults to 443.
        :param scheme: (string) the HTTP scheme to use. http or https. Defaults to https.
        :param timeout: (int) the timeout value in seconds for HTTP requests. Defaults to 30.
        :param verify: (bool) true to enable certificate verification, false to disable. Defaults to true.
        """
        # Allow current number of arguments, it does not affect readability
        # pylint: disable=too-many-arguments

        # Set properties using parameters
        self.session = requests.Session()
        self.last_request = None
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.scheme = scheme
        self.timeout = timeout
        self.verify = verify
        self.log = []
        self.history = []

        # Disable URLLIB3 warnings about invalid certificates
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def version():
        """
        Provides the current version of pfsense vShell
        :return: (string) the current pfSense vShell version
        """
        return __version__

    def url(self):
        """
        Formats a full URL with the objects current property values
        :return: (string) full URL of our object
        """

        return self.scheme + "://" + self.host + ":" + str(self.port)

    def run_command(self, cmd):
        """
        Executes a shell command on the remote host using pfSense's diag_command.php page
        :param cmd: (string) a shell command to execute
        :return: (string) output of the shell command
        """
        # Ensure there are no apparent issues with the target host.
        self.__has_host_errors__()

        # Make our HTTP request.
        payload = {"__csrf_magic": self.get_csrf_token("/diag_command.php"), "txtCommand": cmd, "submit": "EXEC"}
        req = self.request("/diag_command.php", method="POST", data=payload)

        # Write the command executed to the vShell history and log the action.
        self.history.append(cmd)
        self.__log__("run_command", cmd)

        # Check that our output <pre> tags exist
        if "<pre>" in req.text:
            return html.unescape(req.text.split("<pre>")[1].split("</pre>")[0])

        # Return none if we were unable to locate the output
        return None

    def request(self, uri, method="GET", data=None):
        """
        Makes HTTP requests on behalf of our object
        :param uri: (string) the URI (e.g. /index.php) to request on the remote host
        :param method: (string) the HTTP method to use in the request (e.g. POST, GET)
        :param data: (dict) the request body data to send in the request
        :return: (object) the Response object created by the `requests` module
        """

        # Try to make our HTTP request, handle errors accordingly
        try:
            session = self.session
            req = session.request(method, self.url() + uri, data=data, timeout=self.timeout, verify=self.verify)
            session.close()
            self.last_request = req
            self.__log__("request", str(req.status_code) + " " + method + " " + uri)
            return req
        except requests.exceptions.ConnectTimeout as connect_timeout:
            self.__log__("request", str(connect_timeout))
            self.__get_error__(10)
        except requests.exceptions.SSLError as ssl_error:
            self.__log__("request", str(ssl_error))
            self.__get_error__(11)
        except requests.exceptions.ConnectionError as connection_error:
            self.__log__("request", str(connection_error))
            self.__get_error__(12)

        # Return none if we somehow land here
        return None

    def authenticate(self):
        """
        Attempts to authenticate using the objects current properties
        :return: (bool) true if authentication was successful, false if it wasn't
        """

        # Make an initial request to the initialize the CSRF checks.
        pre_auth_req = self.request("/index.php")

        # Format our request payload include the valid CSRF token.
        payload = {
            "__csrf_magic": self.get_csrf_token("/index.php"),
            "usernamefld": self.username,
            "passwordfld": self.password,
            "login": "Sign In"
        }

        # Only authenticate if we are not already authenticated
        if "class=\"fa fa-sign-out\"" not in pre_auth_req.text:
            req = self.request("/index.php", method="POST", data=payload)

            # Attempt to authenticate
            if "username or Password incorrect" not in req.text and "class=\"fa fa-sign-out\"" in req.text:
                self.__log__("authenticate", "success")
                return True
            # Support first time logings where wizard is triggered
            if "<p>One moment while the initial setup wizard starts." in req.text:
                self.__log__("authenticate", "success")
                return True
            # Otherwise, assume authentication failed
            self.__log__("authenticate", "failed")
            return False

        # Don't re-authenticate if we're already authenticated
        return True

    def get_csrf_token(self, uri):
        """
        Retrieves the current CSRF token for a page
        :param uri: (string) the URI (e.g. index.php) to retrieve the CSRF token from
        :return: (string) the valid CSRF token or empty string if no CSRF token was found
        """
        # Initialize CSRF token attributes and make initial CSRF query.
        csrf_token_length = 55
        csrf_token = ""
        csrf_resp = self.request(uri, "GET")

        # Parse CSRF token if it was found
        if "sid:" in csrf_resp.text:
            csrf = "sid:"
            csrf += csrf_resp.text.split("sid:")[1].split(";")[0].replace(" ", "").replace("\n", "").replace("\"", "")
            csrf_token = csrf if len(csrf) is csrf_token_length else ""

        # Return the valid CSRF token, or empty string if it could not be determined.
        return csrf_token

    def has_dns_rebind_error(self, req=None):
        """
        Checks if the objects host encounters a DNS rebind error when connecting
        :param req: (object) optionally provide an existing Response object created by the requests module
        :return: (bool) true if a DNS rebind error was found, false if it wasn't
        """
        # Make a preliminary request to check if a DNS Rebind error was detected by pfSense.
        resp = req.text if req else self.request("/").text
        return "Potential DNS Rebind attack detected" in resp

    def is_host_pfsense(self, req=None):
        """
        Checks if the remote host is running pfSense. This is intended to protect clients from accidentally sending
        their login credentials to the wrong host as well as prevent hosts from spamming non-pfSense hosts.
        :param req: (object) optionally provide an existing Response object created by the requests module
        :return: (bool) true if the host is running pfSense, false if it is not
        """
        # Make a preliminary request to check for keywords that indicate the target is running pfSense.
        resp = req.text if req else self.request("/").text

        platform_confidence = 0

        # List of platform dependent key words to check for
        check_items = [
            "pfSense", "pfsense.org", "Login to pfSense", "pfsense-logo", "pfSenseHelpers",
            "netgate.com", "__csrf_magic", "ESF", "Netgate", "Rubicon Communications, LLC",
            "Electric Sheep Fencing LLC", "https://pfsense.org/license", "CsrfMagic",
            "csrfMagicToken", "/csrf/csrf-magic.js", "wizard.php", "/css/pfSense.css"
        ]
        # Loop through our list and add up a confidence score
        for item in check_items:
            platform_confidence = platform_confidence + 10 if item in resp else platform_confidence

        return platform_confidence > 50

    def __has_host_errors__(self):
        """
        Combines all host-based error checks into a single function.
        :return: (bool) returns true if no errors were, raises PFError if errors were found
        """

        # Ensure remote host is running pfSense
        if not self.is_host_pfsense():
            self.__log__("is_host_pfsense", "platform confidence below threshold")
            self.__get_error__(13)
        # Ensure remote host does not have DNS rebind error
        elif self.has_dns_rebind_error():
            self.__log__("is_host_pfsense", "dns rebind error detected")
            self.__get_error__(14)
        # Ensure we can authenticate
        elif not self.authenticate():
            self.__get_error__(3)

        return False

    def __get_error__(self, code):
        """
        Sets and raises errors. Centralizes error messages.
        :param code: (int) the error code of the error to raise
        :return:
        """
        errors = {
            1: "an unknown error has occurred",
            3: "authentication failed",
            4: "authorization failed",
            10: "connection to '" + self.url() + "' timed-out",
            11: "certificate verification failed",
            12: "could not connect to host at '" + self.url() + "'",
            13: "host at '" + self.url() + "' does not appear to be running pfSense",
            14: "DNS rebind error detected"
        }

        raise PFError(code, errors.get(code, 1))

    def __log__(self, event, msg):
        """
        Appends a new log entry to our log property
        :param event: (string) the method that triggered the log
        :param msg: (string) a descriptive message detailing the log event
        :return: (none) a new item will be appended to the log property of the object
        """
        self.log.append(",".join([str(datetime.datetime.utcnow()), self.url(), self.username, event, msg]))


class PFError(BaseException):
    """Error object used by the PFVShell class"""
