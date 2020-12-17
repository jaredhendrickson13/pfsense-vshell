# Copyright 2020 Jared Hendrickson
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

from setuptools import setup


def read_me():
    with open('README.md') as f:
        return f.read()


setup(
    name='pfsense-vshell',
    author='Jared Hendrickson',
    author_email='jaredhendrickson13@gmail.com',
    url="https://github.com/jaredhendrickson13/pfsense-vshell",
    license="Apache-2.0",
    description="A command line tool to run remote shell commands on pfSense without SSH",
    long_description=read_me(),
    long_description_content_type="text/markdown",
    version="2.0.1",
    scripts=['scripts/pfsense-vshell'],
    packages=["pfsense_vshell"],
    install_requires=[
           "requests",
           "urllib3"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5'
)
