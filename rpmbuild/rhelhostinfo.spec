Name: rhelhostinfo
Summary: Security script to enumerate host information and forward to syslog server
License: BSD3
Requires: systemd openscap-scanner scap-security-guide wget nmap
###### Vars to update with changes: #####
%define version 1
%define release 1%{?dist}
%define buildarch "x86_64"
BuildArch: x86_64
#########################################
Version: %{version}
Release: %{release}

%prep
python3 -m pip install --upgrade pip wheel setuptools 
python3 -m pip install --upgrade distro psutil lxml netifaces numpy
python3 -m pip install --upgrade pyinstaller pyinstaller[encryption]
wget -O %{_sourcedir}/security-data-oval-com.redhat.rhsa-RHEL7.xml.bz2  https://access.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2
wget -O %{_sourcedir}/security-data-oval-com.redhat.rhsa-RHEL8.xml.bz2  https://access.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml.bz2
bzip2 -d %{_sourcedir}/security-data-oval-com.redhat.rhsa-RHEL7.xml.bz2
bzip2 -d %{_sourcedir}/security-data-oval-com.redhat.rhsa-RHEL8.xml.bz2
wget -O %{_sourcedir}/com.redhat.rhsa-all.xccdf.xml http://www.redhat.com/security/data/metrics/com.redhat.rhsa-all.xccdf.xml

%description
send RHEL host data to syslog for compliance and monitoring purposes

%build
pyinstaller %{_sourcedir}/pyinstaller/rhelhostinfo.bin.spec --distpath %{_sourcedir} --clean --log-level=DEBUG

%install
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}/usr/share/doc/rhelhostinfo
mkdir -p %{buildroot}/opt/rhelhostinfo/debug
mkdir -p %{buildroot}/opt/rhelhostinfo/data
mkdir -p %{buildroot}/opt/rhelhostinfo/log
mkdir -p %{buildroot}/opt/rhelhostinfo/runtime
mkdir -p %{buildroot}/opt/rhelhostinfo/scripts
mkdir -p %{buildroot}/opt/rhelhostinfo/log/SCAP
mkdir -p %{buildroot}/usr/share/xml/scap/ssg/content
install -m 644 %{_sourcedir}/LICENSE %{buildroot}/usr/share/doc/rhelhostinfo
install -m 644 %{_sourcedir}/README.md %{buildroot}/usr/share/doc/rhelhostinfo
install -m 644 %{_sourcedir}/CHANGELOG %{buildroot}/usr/share/doc/rhelhostinfo
install -m 644 %{_sourcedir}/CONTRIBUTING.md %{buildroot}/usr/share/doc/rhelhostinfo
install -m 755 %{_sourcedir}/rhelhostinfo.bin %{buildroot}%{_sbindir}/rhelhostinfo
install -m 755 %{_sourcedir}/scripts/scap_report_viewer.sh %{buildroot}/opt/rhelhostinfo/scripts/scap_report_viewer.sh
install -m 755 %{_sourcedir}/scap_tailoring/rhel7-gui-tailoring.xml %{buildroot}/usr/share/xml/scap/ssg/content/rhel7-gui-tailoring.xml
install -m 755 %{_sourcedir}/scap_tailoring/rhel7-no-gui-tailoring.xml %{buildroot}/usr/share/xml/scap/ssg/content/rhel7-no-gui-tailoring.xml
install -m 755 %{_sourcedir}/scap_tailoring/rhel7-rhev-tailoring.xml %{buildroot}/usr/share/xml/scap/ssg/content/rhel7-rhev-tailoring.xml
install -m 755 %{_sourcedir}/scap_tailoring/rhel8-no-gui-tailoring.xml %{buildroot}/usr/share/xml/scap/ssg/content/rhel8-no-gui-tailoring.xml
install -m 755 %{_sourcedir}/scap_tailoring/rhel8-gui-tailoring.xml %{buildroot}/usr/share/xml/scap/ssg/content/rhel8-gui-tailoring.xml
install -m 755 %{_sourcedir}/com.redhat.rhsa-all.xccdf.xml %{buildroot}/usr/share/xml/scap/ssg/content/com.redhat.rhsa-all.xccdf.xml
install -m 755 %{_sourcedir}/security-data-oval-com.redhat.rhsa-RHEL7.xml %{buildroot}/usr/share/xml/scap/ssg/content/security-data-oval-com.redhat.rhsa-RHEL7.xml
install -m 755 %{_sourcedir}/security-data-oval-com.redhat.rhsa-RHEL8.xml %{buildroot}/usr/share/xml/scap/ssg/content/security-data-oval-com.redhat.rhsa-RHEL8.xml

%post
chmod -R 2755 /opt/rhelhostinfo
chmod -R 644 /usr/share/doc/rhelhostinfo
echo "[**] rhelhostinfo successfully installed."
echo "[**] rhelhostinfo documents are located in /usr/share/doc/isrsknr"
echo "[**] run 'rhelhostinfo --help' to see available command-line options"

%files
%{_sbindir}/rhelhostinfo
/opt/rhelhostinfo/debug
/opt/rhelhostinfo/data
/opt/rhelhostinfo/runtime
/opt/rhelhostinfo/scripts
/opt/rhelhostinfo/log
/opt/rhelhostinfo/log/SCAP
/usr/share/xml/scap/ssg/content
/usr/share/doc/rhelhostinfo
/usr/share/doc/rhelhostinfo/CHANGELOG
/usr/share/doc/rhelhostinfo/CONTRIBUTING.md
/usr/share/doc/rhelhostinfo/LICENSE
/usr/share/doc/rhelhostinfo/README.md
%attr(0755, root, root) /opt/rhelhostinfo/scripts/scap_report_viewer.sh
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/com.redhat.rhsa-all.xccdf.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/security-data-oval-com.redhat.rhsa-RHEL7.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/security-data-oval-com.redhat.rhsa-RHEL8.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/rhel7-gui-tailoring.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/rhel7-rhev-tailoring.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/rhel7-no-gui-tailoring.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/rhel8-gui-tailoring.xml
%attr(0755, root, root) /usr/share/xml/scap/ssg/content/rhel8-no-gui-tailoring.xml

%docdir /usr/share/doc/rhelhostinfo
