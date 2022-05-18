## Software Bill of Materials
List of software for building and running the `rhelhostinfo` application

## Application Building / Continuous Integration pipeline
+ Infrastructure requirements: `Gitlab` + `gitlab runner` (pre-existing this application)
+ Docker enterprise container images: `python:latest`, `centos:centos7`, `rockylinux:latest`, and the default shell container
+ packages installed via yum: `groupinstall: "Development Tools"`, `gcc`, `openssl-devel`, `bzip2-devel`, `libffi-devel`, `wget` `rpm-build`, `rpmdevtools`, `nmap`, `zlib-devel`, `gobject-introspection-devel`, `cairo-gobject-devel`, `upx`, `libcmocka-devel`, `sqlite-devel`, `rpm-build`, `rpmdevtools`, and `freetype-devel`
+ python packages installed via yum: `python39`, `python39-devel`, `python39-pip`, `python3-devel`, `pyinstaller`, `pip`, `wheel`, `setuptools`, `flake8`, `bandit`, `black`, `pandas`, and `pytest`
+ python packages installed via pip: `python-dev-tools`, `xcffib`, `cairocffi`, and `tornado` 
+ packages installed via wget/curl: `https://www.python.org/ftp/python/3.9.5/Python-3.9.5.tgz`,
+ packages included with the packaged application and obtained via wget/curl during the CI pipeline: `https://access.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2`, `https://access.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml.bz2`, and `http://www.redhat.com/security/data/metrics/com.redhat.rhsa-all.xccdf.xml`

### Application Software 
+ python3 (Python 3.9.5 for RHEL7, RedHat's packaged python3.9 for RHEL8)
+ python pip packages detailed in the `requirements.txt`

### Requirements to be installed on the OS for the application to run:
+ `systemd`
+ `openscap-scanner`
+ `scap-security-guide`
+ `wget`
+ `nmap`
