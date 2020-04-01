from setuptools import setup

def read_me():
    with open('README.md') as f:
        return f.read()

setup(
    name='pfsense-vshell',
    author='Jared Hendrickson',
    author_email='jaredhendrickson13@gmail.com',
    url="https://github.com/jaredhendrickson13/pfsense-vshell",
    packages=['pfvlib'],
    description="A command line tool to run remote shell commands on pfSense without SSH",
    long_description=read_me(),
    version='0.0.1_3',
    scripts=['pfsense-vshell'],
    install_requires=[
           "requests",
           "urllib3"
    ],
)