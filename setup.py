from setuptools import setup
from pfsense_vshell import PFClient

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
    version=PFClient.version(),
    scripts=['pfsense-vshell'],
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