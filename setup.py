# Copyright 2025 Jared Hendrickson
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
"""Sets up the pfsense-vshell package for distribution.s"""

import codecs
import os

from setuptools import setup


def read(rel_path):
    """Reads a specified file."""
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), "r") as filepath:
        return filepath.read()


def get_version(rel_path):
    """
    Gets the current version of the package. If a __PFSENSE_VSHELL_DEVREVISION__ environment variable exists, it will
    be read and appended to the current package version. This is used to ensure the setup version can always be unique
    for PyPI dev builds triggered by CI/CD workflows.
    """
    # Variables
    revision = ""

    # If a __PFSENSE_VSHELL_DEVREVISION__ environment variable exists, set it as the dev revision.
    if "__PFSENSE_VSHELL_DEVREVISION__" in os.environ:
        revision = "." + os.environ.get("__PFSENSE_VSHELL_DEVREVISION__")

    # Otherwise, look for the version in the package.
    for line in read(rel_path).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1] + revision

    raise RuntimeError("Unable to find version string.")


def read_readme():
    """Reads the README.md for this repository to include in package distributions."""
    return read("README.md")


def read_requirements():
    """Opens and read the requirements.txt file for this repo."""
    with open("requirements.txt", "r", encoding="utf-8") as requirements_file:
        return list(filter(None, requirements_file.read().split("\n")))


setup(
    name="pfsense-vshell",
    author="Jared Hendrickson",
    author_email="github@jaredhendrickson.com",
    url="https://github.com/jaredhendrickson13/pfsense-vshell",
    license="Apache-2.0",
    description="A command line tool to run remote shell commands on pfSense without SSH.",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    version=get_version("pfsense_vshell/__init__.py"),
    scripts=["scripts/pfsense-vshell"],
    packages=["pfsense_vshell"],
    install_requires=read_requirements(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.5",
)
