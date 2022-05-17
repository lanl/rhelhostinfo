#!/bin/env python3
# external imports
import os
import sys
import platform
import subprocess

"""
If you aren't familiar with the openscap project, reading the source docs will give you a better understanding 
of the capabilities and functionality than the limited subset of uses presented here.

Note the rpm install process needs to create this directory structure: 
"/opt/rhelhostinfo/log/SCAP" as ("0770", 'root', 'root').

Note that in  the rpm install process we need the files for the os's below retrieved and put in the directory from 
which oscap is run (aka the root application directory since we are using shell calls from within it)
`wget -O security-data-oval-com.redhat.rhsa-RHEL7.xml https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml`

to audit for sw vulns per rhel oscap:
`wget http://www.redhat.com/security/data/metrics/com.redhat.rhsa-all.xccdf.xml`

initiate the audit the host with:
`oscap oval eval --results rhsa-results-oval.xml --report oval-report.html com.redhat.rhsa-all.xccdf.xml`

Note that the tailoring files need to be copied from ../scap_tailoring/*.xml to /usr/share/xml/scap/ssg/content
and this is done in the rpm install phase
"""


class ConfigHardening:
    """
    this class is used to manipulate the openscap utility provided with RHEL to
    scan the host, provide configuration vulnerability reporting, and auto remediate
    known vulnerable configurations to a STIG baseline that can be tailored by host or business need
    """

    def __init__(self):
        """
        moved the yum installation stuff to a requires statement in the rpm .spec file, retaining the
        content below for future use or running natively in python for development
        yum_packages_installed = subprocess.check_output(["rpm", "-qa", "openscap-scanner", "scap-security-guide"]).decode("utf-8")
        if yum_packages_installed != 0:
            try_to_install = subprocess.check_output(["yum", "install", "-y",
                 "openscap-scanner", "scap-security-guide"]).decode("utf-8")

        general openscap notes if you don't want to read the docs:
        -to use the oscap/openscap utility the scanner and security guides must be installed
        -this installs the content into /usr/share/xml/scap/ssg/content/
        -as of this writing, the firefox and jre application content is provided
        -also the rhel6, 7, & 8 os content is provided
        -the generic profile names are standarized across the redhat-releases, we mod them here to allow tailoring
        -the tailoring files are maintained outside of this application's directory to provide independence / allow
        you to maintain them with your SCM tool of choice if you want to have individual host configurations versus
        blanket / generic settings, just have your scm tool replace the tailoring file appropriately post-install
        """
        # set all the default variables
        self.default_gui_profile = "xccdf_org.ssgproject.content_profile_stig_gui"
        self.default_profile = "xccdf_org.ssgproject.content_profile_stig"
        self.gui_profile = "xccdf_gov.lanl_profile_stig_gui_customized"
        self.no_gui_profile = "xccdf_gov.lanl_profile_stig_customized"
        self.rhev_profile = "xccdf_gov.lanl_profile_rhelh-stig_customized"
        self.in_dir = "/usr/share/xml/scap/ssg/content"
        self.out_dir = "/opt/rhelhostinfo/log/SCAP"
        self.start_cmd = "oscap xccdf eval "
        self.fetch_remote_cmd = "--fetch-remote-resources "
        self.check_firefox = False
        self.check_jre = False
        self.check_gui = False
        self.check_rhev = False
        self.check_tailoring = False
        self.starting_dir = os.getcwd()
        # capture hostname for file naming
        self.hostname = platform.node()
        # capture os version for appropriate security content and tailoring
        self.release = platform.uname().release
        self.release = str(self.release).split(".")
        for element in self.release:
            if "el" in element:
                self.release = element
        self.release = self.release.replace("el", "")
        # set the release or hostname dependent data members
        self.remediation_script = (
            f"{self.out_dir}/{self.hostname}-remediation-script.sh"
        )
        self.out_xccdf_xml = f"{self.out_dir}/{self.hostname}_scap_results.xml"
        self.out_xml_arf = f"{self.out_dir}/{self.hostname}_scap_results_arf.xml"
        self.out_rpt = f"{self.out_dir}/{self.hostname}_scap_report.html"
        self.gui_tailoring_filename = (
            f"{self.in_dir}/rhel{self.release}-gui-tailoring.xml"
        )
        self.no_gui_tailoring_filename = (
            f"{self.in_dir}/rhel{self.release}-no-gui-tailoring.xml"
        )
        self.rhev_tailoring_filename = (
            f"{self.in_dir}/rhel{self.release}-rhev-tailoring.xml"
        )
        self.benchmark_id = (
            f"xccdf_org.ssgproject.content_benchmark_RHEL-{self.release}"
        )
        # set the default profile and tailoring information
        self.profile = self.no_gui_profile
        self.tailoring_filename = self.no_gui_tailoring_filename
        # set data members that will be changed later
        self.oscap_remediate_if_jre_cmd = str()
        self.oscap_report_if_jre_cmd = str()
        self.oscap_remediate_if_firefox_cmd = str()
        self.oscap_report_if_firefox_cmd = str()
        self.oscap_remediate_os_cmd = str()
        self.oscap_report_os_cmd = str()
        self.sw_vulns = str()
        self.gen_remediation_script = str()

    def set_variables(self):
        """
        set the needed variables / data members for the application, these could change
        (say firefox got installed) so the tailoring of these data members is done prior to
        execution to capture the current state of the host
        """
        # check to see if the appropriate tailoring file exists
        self.check_tailoring = os.path.exists(self.tailoring_filename)
        # capture the output of ("rpm -qa firefox") to determine if firefox is installed
        firefox = subprocess.call(["rpm -q firefox"], shell=True)
        if firefox == 0:
            self.check_firefox = True
        # capture the output of ("rpm -qa jre") to determine if jre is installed
        jre = subprocess.call(["rpm -q jre"], shell=True)
        if jre == 0:
            self.check_jre = True
        # use the output of ("ls /usr/bin/*session") to determine of a gui is installed on the rhel host
        gui = subprocess.check_output(["ls /usr/bin"], shell=True).decode("utf-8")
        if "session" in gui:
            self.check_gui = True
            self.profile = self.gui_profile
            self.tailoring_filename = self.gui_tailoring_filename
            self.default_profile = self.default_gui_profile
        rhev = subprocess.call(["rpm -q hosted-engine"], shell=True)
        if rhev == 0:
            self.check_rhev = True
            self.profile = self.rhev_profile
            self.tailoring_filename = self.rhev_tailoring_filename
        # the profile information that we are interested in for the os scan is the stig and stig_gui scan
        self.oscap_remediate_if_jre_cmd = (
            self.start_cmd + f"--remediate --profile xccdf_org.ssgproject.content_"
            f"profile_stig --results {self.out_dir}/"
            f"{self.hostname}-jre-xccdf-results.xml "
            f"{self.in_dir}/ssg-jre-ds.xml"
        )
        self.oscap_report_if_jre_cmd = (
            self.start_cmd + f"--profile xccdf_org.ssgproject.content_profile_stig "
            f"--results {self.out_dir}/jre-xccdf-results.xml "
            f"{self.in_dir}/ssg-jre-ds.xml"
        )
        self.oscap_remediate_if_firefox_cmd = (
            self.start_cmd + f"--remediate --profile xccdf_org.ssgproject.content_"
            f"profile_stig --results {self.out_dir}/"
            f"{self.hostname}-firefox-xccdf-results.xml "
            f"{self.in_dir}/ssg-firefox-ds.xml"
        )
        self.oscap_report_if_firefox_cmd = (
            self.start_cmd + f"--profile xccdf_org.ssgproject.content_profile_stig "
            f"--results {self.out_dir}/firefox-xccdf-results.xml "
            f"{self.in_dir}/ssg-firefox-ds.xml"
        )
        online = subprocess.call(["wget", "-q", "--spider", "https://google.com"])
        if online == 0:
            self.start_cmd += self.fetch_remote_cmd
        else:
            print(
                "[**] SCAP: system appears to be offline, attempting to set proxy configs to get out to the world."
            )
            os.system("export https_proxy=http://proxyout.lanl.gov:8080")
            online = subprocess.call(["wget", "-q", "--spider", "https://google.com"])
            if online == 0:
                self.start_cmd += self.fetch_remote_cmd
                print("[**] SCAP: system online after proxy was set!")
            else:
                print(
                    "[**] SCAP: system unable to reach the internet, continuing with local openscap resources"
                )
        if self.check_tailoring:
            self.start_cmd += f" --tailoring-file {self.tailoring_filename} "
        self.oscap_remediate_os_cmd = (
            self.start_cmd + f" --remediate "
            f"--profile {self.profile} --results {self.out_xccdf_xml} "
            f"--results-arf {self.out_xml_arf} --report "
            f"{self.out_rpt} {self.in_dir}/ssg-rhel{self.release}-ds.xml"
        )
        self.oscap_report_os_cmd = (
            self.start_cmd
            + f" --profile {self.profile} --results {self.out_xccdf_xml} "
            f" --results-arf {self.out_xml_arf} --report {self.out_rpt} "
            f"{self.in_dir}/ssg-rhel{self.release}-ds.xml"
        )
        self.sw_vulns = (
            f"oscap oval eval --results {self.out_dir}/{self.hostname}_rhsa-results-oval.xml --report "
            f"{self.out_dir}/{self.hostname}_oval-report.html {self.in_dir}/security-data-oval-com.redhat.rhsa-RHEL{self.release}.xml"
        )
        gen_script = f"oscap xccdf generate fix "
        if online == 0:
            gen_script += "--fetch-remote-resources "
        self.gen_remediation_script = (
            gen_script + f" --template urn:xccdf:fix:script:sh "
            f"--profile {self.default_profile} --output "
            f"{self.remediation_script} "
            f"{self.in_dir}/ssg-rhel{self.release}-ds.xml"
        )

    def oscap_remediate(self):
        """
        run the scans of the host and then remediate, but only remediate if a tailoring file exists
        """
        self.set_variables()
        if self.check_tailoring:
            try:
                os.chdir(self.in_dir)
                print(f"[**] SCAP: including tailoring file: {self.tailoring_filename}")
                if self.check_firefox:
                    print(
                        f"[**] SCAP: Firefox installed on {self.hostname}, continuing to remediate...."
                    )
                    remediate_ff_val = subprocess.call([self.oscap_remediate_if_firefox_cmd], shell=True)
                    msg = f"[**] SCAP: Firefox STIG remediation ran with error code {remediate_ff_val}"
                    print(msg)
                if self.check_jre:
                    print(
                        f"[**] SCAP: JRE installed on {self.hostname}, continuing to remediate...."
                    )
                    remediate_jre_val = subprocess.call([self.oscap_remediate_if_jre_cmd], shell=True)
                    msg = f"[**] SCAP: JRE STIG remediation ran with error code {remediate_jre_val}"
                    print(msg)
                print(
                    f"[**] SCAP: continuing to remediate the operating system to a STIG baseline...."
                )
                check_val = subprocess.call([self.oscap_remediate_os_cmd], shell=True)
                msg = f"[**] SCAP: OS STIG remediation ran with error code {check_val}"
                os.chdir(self.starting_dir)
                return msg
            except Exception as err:
                return err
        else:
            # the else option could be dangerous in case the packaging of the tailoring file fails...
            # probably better to leave alone
            print(
                f"[**] SCAP: No tailoring file found at {self.tailoring_filename}, proceeding to exit..."
            )
            sys.exit(1)

    def oscap_report(self):
        """
        run the scans of the host to enable reporting, but only if a tailoring file exists
        """
        self.set_variables()
        if self.check_tailoring:
            try:
                os.chdir(self.in_dir)
                print(f"[**] SCAP: including tailoring file: {self.tailoring_filename}")
                if self.check_firefox:
                    print(
                        f"[**] SCAP: Firefox installed on {self.hostname}, continuing to report...."
                    )
                    check_ff_val = subprocess.call([self.oscap_report_if_firefox_cmd], shell=True)
                    msg = f"[**] SCAP: Firefox STIG check ran with error code {check_ff_val}"
                    print(msg)
                if self.check_jre:
                    print(
                        f"[**] SCAP: JRE installed on {self.hostname}, continuing to report...."
                    )
                    check_jre_val = subprocess.call([self.oscap_report_if_jre_cmd], shell=True)
                    msg = f"[**] SCAP: JRE STIG check ran with error code {check_jre_val}"
                    print(msg)
                print(
                    f"[**] SCAP: continuing to report / compare the operating system to a STIG baseline...."
                )
                check_val = subprocess.call([self.oscap_report_os_cmd], shell=True)
                msg = f"[**] SCAP: OS STIG check ran with error code {check_val}"
                os.chdir(self.starting_dir)
                return msg
            except Exception as err:
                return err
        else:
            # the else option could be dangerous in case the packaging of the tailoring file fails...
            # probably better to leave alone
            print(
                f"[**] SCAP: No tailoring file found at {self.tailoring_filename}, proceeding to exit..."
            )
            sys.exit(1)

    def oscap_view(self):
        """call the bash oscap viewer script to view the most recent scap report"""
        try:
            test_call = subprocess.call("/bin/bash /opt/rhelhostinfo/scripts/scap_report_viewer.sh", shell=True)
            if test_call != 0:
                print(f"[**] SCAP: /opt/rhelhostinfo/scripts/scap_report_viewer.sh did not run successfully.")
        except Exception as err:
            print(err)

    def rhel_sw_vulns(self):
        """
        use the rhel sw vuln data to identify sw vulns on the host -
        requires that the data is pulled from rhel in a timely manner and
        put in the 'self.in_dir' data member location
        """
        self.set_variables()
        if os.path.exists(f"/usr/share/xml/scap/ssg/content/security-data-oval-com.redhat.rhsa-RHEL{self.release}.xml"):
            try:
                os.chdir(self.in_dir)
                test_if_succeeds = subprocess.call(self.sw_vulns, shell=True)
                msg = f"[**] SCAP: openscap sw vuln assessment FAILED on {self.hostname} using '{self.sw_vulns}'."
                if test_if_succeeds == 0:
                    msg = f"[**] SCAP: openscap sw vuln assessment ran successfully on {self.hostname} using " \
                          f"'{self.sw_vulns}'."
                os.chdir(self.starting_dir)
                print(msg)
                return msg
            except Exception as err:
                return err
        else:
            print(
                f"[**] SCAP: No vuln data file found, check if system can access redhat.con, proceeding to exit..."
            )
            sys.exit(1)

    def report_tailoring(self) -> list:
        """
        report the contents of the scap tailoring file (used in case this has changed from the default)
        """
        if self.check_tailoring:
            print(f"[**] SCAP: including tailoring file: {self.tailoring_filename}")
            cleaned_tailoring_list = list()
            with open(self.tailoring_filename, "r") as tailoring_file:
                tailoring_file = tailoring_file.read()
                for line in tailoring_file:
                    line = line.strip()
                    cleaned_tailoring_list.append(line)
            return cleaned_tailoring_list
        else:
            return [
                f"[**] SCAP: no tailoring file found on {self.hostname}",
            ]

    def generate_remediation_script(self):
        """generate a remediation shell script for remediating a host to the stig baseline"""
        self.set_variables()
        try:
            os.chdir(self.in_dir)
            gen_bash = subprocess.call(self.gen_remediation_script, shell=True)
            msg = (
                f"[**] SCAP: FAILED to generated a bash openscap remediation script on {self.hostname} at "
                f"{self.remediation_script} using '{self.gen_remediation_script}'."
            )
            if gen_bash == 0:
                msg = (
                    f"[**] SCAP: successfully generated a bash openscap remediation script on {self.hostname} at "
                    f"{self.remediation_script} using '{self.gen_remediation_script}'."
                )
                print(
                    "[**] SCAP: use the generated remediation script carefully because it does not include "
                    "organizational tailoring."
                )
            os.chdir(self.starting_dir)
            print(msg)
            return msg
        except Exception as err:
            return err


# run the remediation suite
def main():
    scap = ConfigHardening()
    scap.oscap_remediate()
    scap.oscap_view()


if __name__ == "__main__":
    main()
