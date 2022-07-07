import unittest
import os
import copy
import pfsense_vshell


class TestVShell(unittest.TestCase):
    """Test the pfsense_vshell.PFClient object methods and attributes."""

    # Set attributes
    vshell = None

    def setUp(self):
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
        non_pfsense_vshell.host = "google.com"
        self.assertFalse(non_pfsense_vshell.is_host_pfsense())

    def test_run_command(self):
        """Ensure specific commands produce an expected output."""
        # Ensure working directory is pfSense webroot.
        self.assertEqual(self.vshell.run_command("pwd"), "/usr/local/www")

        # Ensure current user is pfSense root.
        self.assertEqual(self.vshell.run_command("whoami"), "root")

        # Ensure executed commands are registered in the vshell history.
        self.assertIn("pwd", self.vshell.history)
        self.assertIn("whoami", self.vshell.history)


if __name__ == '__main__':
    unittest.main()
