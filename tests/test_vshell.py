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
"""Tests the pfsense_vshell package."""

import unittest
import os
import copy
import pfsense_vshell


class TestVShell(unittest.TestCase):
    """Test the pfsense_vshell.PFClient object methods and attributes."""

    # Set attributes
    vshell = None

    def setUp(self):
        """Define attributes required for test methods."""
        # Define the vshell attribute
        self.vshell = pfsense_vshell.PFClient(
            os.environ.get("PFSENSE_VSHELL_HOST", "localhost"),
            username=os.environ.get("PFSENSE_VSHELL_USERNAME", "admin"),
            password=os.environ.get("PFSENSE_VSHELL_PASSWORD", "pfsense"),
            port=int(os.environ.get("PFSENSE_VSHELL_PORT", 443)),
            scheme=os.environ.get("PFSENSE_VSHELL_SCHEME", "https"),
            timeout=int(os.environ.get("PFSENSE_VSHELL_TIMEOUT", 30)),
            verify=bool(os.environ.get("PFSENSE_VSHELL_VERIFY", False))
        )

    def test_get_csrf_token(self):
        """Ensure we are able to fetch the CSRF token and it is a valid length."""
        self.assertEqual(len(self.vshell.get_csrf_token("/index.php")), 55)

    def test_authenticate(self):
        """Ensure we are able to determine successful authentication from failed authentication."""
        # Check bad authentication using a clone of the PFClient object
        bad_auth_vshell = copy.deepcopy(self.vshell)
        bad_auth_vshell.username = "INVALID"
        bad_auth_vshell.password = "INVALID"
        self.assertFalse(bad_auth_vshell.authenticate())

        # Check good authentication.
        self.assertTrue(self.vshell.authenticate())

    def test_is_host_pfsense(self):
        """Ensure module can accurate tell if a host is running pfSense."""
        # Check if module correctly identifies pfSense host.
        self.assertTrue(self.vshell.is_host_pfsense())

        # Check if module correctly identifies non-pfSense host using a clone of the PFClient object
        non_pfsense_vshell = copy.deepcopy(self.vshell)
        non_pfsense_vshell.host = "example.com"
        non_pfsense_vshell.port = 80
        non_pfsense_vshell.scheme = "http"
        self.assertFalse(non_pfsense_vshell.is_host_pfsense())

    def test_has_dns_rebind_error(self):
        """Ensures the 'has_dns_rebind_error' method successfully checks for DNS rebinds errors."""
        self.assertFalse(self.vshell.has_dns_rebind_error())

    def test_run_command(self):
        """Ensure specific commands produce an expected output."""
        # Ensure working directory is pfSense webroot.
        self.assertEqual(self.vshell.run_command("pwd"), "/usr/local/www")

        # Ensure current user is pfSense root.
        self.assertEqual(self.vshell.run_command("whoami"), "root")

        # Ensure executed commands are registered in the vshell history.
        self.assertIn("pwd", self.vshell.history)
        self.assertIn("whoami", self.vshell.history)

    def test_version(self):
        """Ensure the version method returns the correct version."""
        self.assertEqual(self.vshell.version(), pfsense_vshell.__version__)

    def test_url(self):
        """Ensure the url method correctly formats the URL."""
        self.assertEqual(
            self.vshell.url(),
            self.vshell.scheme + "://" + self.vshell.host + ":" + str(self.vshell.port)
        )

    def test_get_error(self):
        """Ensure the __get_error__ method raises the error correctly."""
        with self.assertRaises(pfsense_vshell.PFError):
            self.vshell.__get_error__(1)

    def test_has_host_errors(self):
        """Ensure the __has_host_errors__ properly checks for any host errors."""
        # Check that our main test target is correclty identified as having no errors
        self.assertFalse(self.vshell.__has_host_errors__())

        # Create a new test target that has bad authentication to ensure the method catches it
        non_pfsense_vshell = copy.deepcopy(self.vshell)
        non_pfsense_vshell.session.cookies.clear_session_cookies()
        non_pfsense_vshell.username = "INVALID"
        non_pfsense_vshell.password = "INVALID"
        self.assertRaises(pfsense_vshell.PFError, non_pfsense_vshell.__has_host_errors__)

        # Check if module correctly identifies non-pfSense host using a clone of the PFClient object
        non_pfsense_vshell.username = self.vshell.username
        non_pfsense_vshell.password = self.vshell.password
        non_pfsense_vshell.host = "example.com"
        non_pfsense_vshell.port = 80
        non_pfsense_vshell.scheme = "http"
        self.assertRaises(pfsense_vshell.PFError, non_pfsense_vshell.__has_host_errors__)

    def test_log(self):
        """Ensure the __log__ method logs events properly."""
        self.vshell.__log__("TESTEVENT", "TESTMSG")

        # Checks to ensure the message was actually logged.
        with self.assertRaises(EOFError):
            for log in self.vshell.log:
                if "TESTEVENT" in log and "TESTMSG" in log:
                    raise EOFError

    def test_pferror_class(self):
        """Tests the PFError exception class."""
        with self.assertRaises(pfsense_vshell.PFError):
            raise pfsense_vshell.PFError


if __name__ == '__main__':
    unittest.main()
