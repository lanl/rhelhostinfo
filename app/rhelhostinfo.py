#!/bin/env/python3
# rhelhostinfo.py: host state configuration enumeration

# Import statements for all standard libraries
import subprocess
from datetime import date
from datetime import timedelta
from datetime import datetime
import sys
import os
import os.path
import glob
import re
import platform
import traceback
import netifaces
import psutil
import distro
from lxml import etree
import logging
import logging.config
import logging.handlers
from app.state import State


class RhelHostInfo(State):
    """enumerate host for security-relevant information"""

    def __init__(self):
        super().__init__()
        
        #### ORG Specific LDAP Vars, need to edit appropriately ####
        # uses an anonymous bind to check ldap for valid organizational users & hosts
        self.ldap_server = None
        self.ldap_ou_name = None
        self.ldap_dc_name = None # may have more than 1
        self.ldap_ip_name = None 
        self.ldap_property_field = None
        self.ldap_owner_field = None
        self.ldap_employee_id_field = None
        self.ldap_authorized_user_field = None
        ################## End LDAP required Vars ##################
        
        # Define today's date to use to identify the running of this script
        self.apps_list = list()
        self.date = date.today()
        self.hostname = platform.node()
        self.hostowner = str()
        self.hwinfo_list = list()
        self.hwpropnum = str()
        self.int_list = list()
        self.interfaces = netifaces.interfaces()
        self.ipaddrpri = str()
        self.macaddr = str()
        self.macaddrs_list = list()
        self.machine = platform.uname().machine
        self.non_org_users = list()
        self.org_users = list()
        self.processor = platform.uname().processor
        self.process_list = list()
        self.rhel = distro.id()
        self.rhel_name = distro.name()
        self.rhel_release = platform.uname().release
        self.rhel_version = distro.version()
        self.rhel_version_date = platform.uname().version
        self.root_change_bool = False
        self.root_change_str = str()
        self.sestatus_list = list()
        self.service_accounts = list()
        self.sudoers_list = list()
        self.time_list = list()
        self.user_accounts = list()

    # Define all accounts on the host
    def accounts(self):
        # user account here is any account with login ability to the host
        # service account here is any account without login ability to the host
        with open("/etc/passwd", "r") as passwdfile:
            search_string = "nologin"
            search_list = ["sync", "shutdown", "halt"]
            for line in passwdfile:
                if search_string in line:
                    service_name = line.split(":")[0]
                    self.service_accounts.append(service_name.strip())
                elif search_string not in line:
                    username = line.split(":")[0]
                    for item in search_list:
                        if item == username.strip():
                            continue
                    self.user_accounts.append(username.strip())
        user_accounts = "User_Accounts=" + " ".join(self.user_accounts)
        service_accounts = "Service_Accounts=" + " ".join(self.service_accounts)
        account_string = user_accounts + ";" + service_accounts
        return account_string

    # Define non-organizational accounts via an ldap lookup
    def inspect_accounts(self):
        search_list = ["sync", "shutdown", "halt", "root"]
        for user in self.user_accounts:
            if user not in search_list:
                if not self.ldap_dc_name:
                    print(f"Could not look up user {user} in ldap / need to configure ldap variables in rhelhostinfo.py")
                    continue
                check_user_cmd = f"ldapsearch -x -h dir1 -b {self.ldap_dc_name} uid={user}"
                user_data = subprocess.check_output(
                        [check_user_cmd], shell=True
                    ).decode("utf-8")
                if not self.ldap_authorized_user_field in user_data:
                  self.non_org_users.append(user)
        if not self.non_org_users:
            users = "Non_Org_Accounts=False"
        users = " ".join(self.non_org_users)
        return ("Non_Org_Accounts=True;Non_Org_Users=" + users)

    # Define the Host's network interfaces
    def interface_info(self):
        interfaces = " ".join(self.interfaces)
        try:
            ipaddrpri_cmd = r"/bin/hostname --all-ip-addresses | awk '{{print $1}}'"
            ipaddrpri = subprocess.Popen(
                [ipaddrpri_cmd],
                cwd=self.debug_path,
                stdout=subprocess.PIPE,
                encoding="utf-8",
                universal_newlines=True,
                shell=True,
            ).communicate()[0]
            self.ipaddrpri = str(ipaddrpri).strip()
        except:
            self.ipaddrpri = (
                f"Error attempting to obtain primary ip information on {self.hostname}"
            )
        try:
            macaddr_cmd = r"/sbin/ifconfig | grep ether | awk '{{print $2}}'"
            macaddr = subprocess.Popen(
                [macaddr_cmd],
                cwd=self.debug_path,
                stdout=subprocess.PIPE,
                encoding="utf-8",
                universal_newlines=True,
                shell=True,
            ).communicate()[0]
            macaddr = macaddr.split()
            self.macaddrs_list = macaddr
            self.macaddr = macaddr[0]
        except:
            self.macaddr = f"Error attempting to obtain primary mac addr information on {self.hostname}"
        interface_str = f"Interface_Names={interfaces};Primary_IP={self.ipaddrpri};MAC_Address={self.macaddr}"
        return interface_str

    # Define the Host's currently installed applications and packages w/ version numbers and repos
    def apps(self):
        # note that yum is in /usr/bin/yum for rhel6 and /bin/yum for rhel7
        # alas atm the yum api and rpm don't currently appear to have compatibility with rhel7/python3
        # divide apps into smaller messages as their total message length will commonly exceed syslog max message length
        try:
            apps_test = subprocess.call(
                ["/bin/yum", "list", "installed"], cwd=self.debug_path
            )
            if apps_test == 0:
                apps = subprocess.check_output(
                    ["/bin/yum", "list", "installed"], cwd=self.debug_path
                ).decode("utf-8")
        except Exception:
            # yum can be misconfigured or have a variety of error states that prevents clean output
            error = traceback.format_exc()
            error = str(error.strip())
            error = error.replace("\n", ";")
            msg = (
                f"Error retrieving a list of currently installed applications with rhelsknr on "
                f"{self.hostname}; error='{error}'"
            )
            sys.stderr.write(msg)
            return msg
        apps = apps.replace("Installed Packages", "")
        apps = re.sub(r"\n+", ";", apps)
        apps = re.sub(r"\t+", ",", apps)
        apps = re.sub(r"\s+", ",", apps)
        apps = apps.replace(",;", ";")
        apps = apps.replace(",,", ",")
        apps = apps.replace(";;", ";")
        apps = apps.split(";")[2:]
        self.apps_list = apps
        evens = apps[: (len(apps) // 2)]
        odds = apps[((len(apps) // 2) + 1) :]
        apps1_list = apps[: (len(evens) // 2)]
        apps2_list = apps[((len(evens) // 2) + 1) :]
        apps3_list = apps[: (len(odds) // 2)]
        apps4_list = apps[((len(odds) // 2) + 1) :]
        apps1_str = "Installed_Packages1=" + " ".join(apps1_list)
        apps2_str = "Installed_Packages2=" + " ".join(apps2_list)
        apps3_str = "Installed_Packages3=" + " ".join(apps3_list)
        apps4_str = "Installed_Packages4=" + " ".join(apps4_list)
        return apps1_str, apps2_str, apps3_str, apps4_str

    # Define the Host time in UTC, ntp sync status, etc.
    def time(self):
        try:
            time_test = subprocess.call(["/bin/timedatectl"], cwd=self.debug_path)
            if time_test == 0:
                time = subprocess.check_output(
                    ["/bin/timedatectl"], cwd=self.debug_path
                ).decode("utf-8")
                time = re.sub(r"\n", ";", time)
                time = time.replace(": ", "=")
                time = time.replace("  ", "")
                time = time.replace(" ", "_")
                time = time.replace(";_", ";")
                time = time.replace(",-", "-")
                time = time.replace(",_", "")
                time = time.split(";")
                self.time_list = time[0:8]
            else:
                raise Exception
        except:
            time_test2 = subprocess.call(
                ["/sbin/hwclock"],
                cwd=self.debug_path,
            )
            if time_test2 == 0:
                time = "Time="
                clocktime = (
                    subprocess.check_output(
                        ["/sbin/hwclock"],
                        cwd=self.debug_path,
                    )
                    .decode(sys.stdout.encoding)
                    .strip()
                )
                time += clocktime
                ntp_cmd = "/usr/bin/ntpstat"
                ntptimeout = subprocess.Popen(
                    [ntp_cmd],
                    cwd=self.debug_path,
                    stdout=subprocess.PIPE,
                    universal_newlines=True,
                ).communicate()[0]
                ntptimeerr = subprocess.Popen(
                    [ntp_cmd],
                    cwd=self.debug_path,
                    stdout=subprocess.PIPE,
                    universal_newlines=True,
                ).communicate()[1]
                ntptimeout = str(ntptimeout).strip()
                ntptimeerr = str(ntptimeerr).strip()
                ntptimeout = ntptimeout.replace(" ", "_")
                ntptimeout = ntptimeout.replace("__", " ")
                if ntptimeout == "":
                    syncstat = ";NTP_synchronized=no"
                    time += syncstat
                    time = time.replace(" ", ";")
                else:
                    time += ntptimeout
                self.time_list = time.split(";")
            else:
                self.time_list = [
                    "Error with 'timedatectl' command",
                    "Error with 'hwclock' and 'ntpstat' commands",
                ]
        time = " ".join(self.time_list)
        return time

    # Define the Host's full interface information
    def ifaddrall(self):
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    addr_list = [addr.address, addr.netmask, addr.broadcast]
                    no_none_list = [val for val in addr_list if val != None]
                    no_efffs_list = [
                        val for val in no_none_list if "ffff:ffff" not in val
                    ]
                    no_zeros_list = [
                        val for val in no_efffs_list if val != "00:00:00:00:00:00"
                    ]
                    no_doublefs_list = [
                        val for val in no_zeros_list if val != "ff:ff:ff:ff:ff:ff"
                    ]
                    no_percent_list = [
                        val for val in no_doublefs_list if "%" not in val
                    ]
                    if not no_percent_list:
                        continue
                    item = f"{name}=" + " ".join(no_percent_list)
                    self.int_list.append(item)
        except:
            ifaddrall_err = "Error with psutil.net_if_addrs(), check if psutil version >= 3.0, only returning IP information"
            ifaddrall_cmd = f"/sbin/ip addr | for x in 'grep inet'; do echo $(awk -F'[ /]' '/inet /{{print $6}}'); done"
            ifaddrall = subprocess.Popen(
                [ifaddrall_cmd],
                cwd=self.debug_path,
                stdout=subprocess.PIPE,
                encoding="utf-8",
                universal_newlines=True,
                shell=True,
            ).communicate()[0]
            self.int_list = ifaddrall.split(" ")
            self.int_list.append(ifaddrall_err)
        return " ".join(self.int_list)

    # Define the Host's property number and owner
    def propinfo(self):
        if not self.ldap_server:
            msg = f"Could not look up host owner or host property information in ldap / need to configure ldap variables in rhelhostinfo.py"
            print(msg)
            return msg
        try:
            host_info_cmd = f"/bin/ldapsearch -x -h {self.ldap_server} -s one -b '{self.ldap_ou_name},{self.ldap_dc_name}' '({self.ldap_ip_name}={self.ipaddrpri})'"
            host_obj = subprocess.Popen(
                host_info_cmd,
                cwd=self.debug_path,
                stdout=subprocess.PIPE,
                encoding="utf-8",
                universal_newlines=True,
                shell=True,
            )
            host_text = host_obj.communicate()[0]
            host_list = host_text.split("\n")
            for item in host_list:
                if f"{self.ldap_property_field}:" in item:
                    self.hwpropnum = item.split(": ")[1].strip()
                if f"{self.ldap_owner_field}:" in item:
                    item.replace("owner: ", "")
                    self.hostowner = item.split(",")[0]
                    self.hostowner.replace(f"{self.ldap_employee_id_field}=", "")
                else:
                    continue
            if self.hwpropnum == "":
                self.hwpropnum = "No_LDAP_response"
            if self.hostowner == "":
                self.hostowner = "No_LDAP_response"
            propinfo = (
                f"ldap_hwpropnum={self.hwpropnum};ldap_hostowner={self.hostowner}"
            )
            return propinfo
        except:
            # may have issues with ldap
            error = traceback.format_exc()
            error = str(error.strip())
            error = error.replace("\n", ";")
            sys.stderr.write(
                f"Error executing ldap queries with rhelsknr on {self.hostname}; error='{error}'"
            )
            propinfo = f"ldap_hwpropnum=LDAP_error;ldap_hostowner=LDAP_error"
            return propinfo

    # Define the Serial Number, Asset Tag (if tagged), Manufacturer, Make/Model and BIOS information
    def hwinfo(self):
        search_list = [
            "Vendor:",
            "Version:",
            "Release Date:",
            "BIOS Revision:",
            "Firmware Revision:",
            "Manufacturer:",
            "Product Name:",
            "Serial Number:",
            "UUID:",
            "Asset Tag:",
        ]
        worthless = "Not Specified"
        hwinfo = list()
        try:
            hwinfo_test = subprocess.call(
                ["/sbin/dmidecode --type 0,1,3"], cwd=self.debug_path, shell=True
            )
            if hwinfo_test == 0:
                hwinfo1 = subprocess.check_output(
                    ["/sbin/dmidecode --type 0"], cwd=self.debug_path, shell=True
                ).decode("utf-8")
                hwinfo1 = hwinfo1.splitlines()
                for line in hwinfo1:
                    for desired in search_list:
                        if worthless in line:
                            continue
                        if desired in line:
                            hwinfo.append(line)
                hwinfo2 = subprocess.check_output(
                    ["/sbin/dmidecode --type 1"], cwd=self.debug_path, shell=True
                ).decode("utf-8")
                hwinfo2 = hwinfo2.splitlines()
                for line in hwinfo2:
                    for desired in search_list:
                        if worthless in line:
                            continue
                        if desired in line:
                            hwinfo.append(line)
                hwinfo3 = subprocess.check_output(
                    ["/sbin/dmidecode --type 3"], cwd=self.debug_path, shell=True
                ).decode("utf-8")
                hwinfo3 = hwinfo3.splitlines()
                for line in hwinfo3:
                    for desired in search_list:
                        if worthless in line:
                            continue
                        if desired in line:
                            hwinfo.append(line)
                hwinfo = ";".join(hwinfo)
                hwinfo = hwinfo.strip()
                hwinfo = hwinfo[1:]
                hwinfo = hwinfo.replace("\t", ";")
                hwinfo = hwinfo.replace(" ", "")
                hwinfo = hwinfo.replace(":", "=")
                self.hwinfo_list = hwinfo.split(";")
                hwinfo = " ".join(self.hwinfo_list)
        except Exception as err:
            hwinfo = f"'Check permissions on {self.hostname} due to error with the '/sbin/dmidecode --type 0,1,3' command"
            print(err)
            hwinfo += err
        return hwinfo

    # Define the current status of SELinux (enabled / disabled / permissive /enforcing)
    def sestatus(self):
        sestatus = None
        sestatus_list = list()
        try:
            sestatus_test = subprocess.call(
                ["/sbin/sestatus"],
            )
            if sestatus_test == 0:
                sestatus = subprocess.check_output(
                    ["/sbin/sestatus"],
                ).decode("utf-8")
                for line in sestatus.split("\n"):
                    line = str(line)
                    line = line.replace(":", "=")
                    line = line.replace("\t+", "")
                    line = line.replace(" ", "")
                    line = line.strip()
                    if line == "":
                        continue
                    sestatus_list.append(line)
                self.sestatus_list = sestatus_list
                sestatus = " ".join(sestatus_list)
            else:
                sestatus = "Error with sestatus command"
        except:
            sestatus = "Error with sestatus command"
        sestatus = "SELinux_status=" + sestatus
        return sestatus

    # Define the sudoers privileges on the host
    def sudoers(self):
        sudoers_contents = list()
        try:
            with open("/etc/sudoers", "r", encoding="utf-8") as sudoersmain:
                for line in sudoersmain:
                    sudoers_contents.append(line.strip())
            more_exists = os.path.exists("/etc/sudoers.d/")
            if more_exists:
                for file_name in glob.glob("/etc/sudoers.d/*"):
                    with open(file_name, "r", encoding="utf-8") as sudoers_file:
                        for line in sudoers_file:
                            sudoers_contents.append(line.strip())
        except Exception:
            error = traceback.format_exc()
            error = str(error.strip())
            error = error.replace("\n", ";")
            msg = (
                f"Error retrieving a list of currently installed applications with rhelhostinfo on "
                f"{self.hostname}; error='{error}'"
            )
            sys.stderr.write(msg)
            return msg
        nohash = [line for line in sudoers_contents if "#" not in line]
        nonewline = [line for line in nohash if not line == "\n"]
        for line in nonewline:
            line = line.replace("\t+", "")
            line = line.replace("Defaults", "")
            line = line.replace(" ", "")
            self.sudoers_list.append(line.strip())
        sudoers_msg = "Sudoers_Entries=" + " ".join(self.sudoers_list)
        return sudoers_msg

    # Define the age of the root password and compare its last-change-date to the frequency it is supposed to be changed
    # 179 days is used here to ensure we have leeway to not violate a 180 day policy.
    def root_change(self):
        # chage for rhel6 & 7 are in different locations
        # possibility that root pw was never set
        root_test = str()
        root_change = str()
        try:
            is_root_set = 'cat /etc/shadow | grep "root"'
            is_root_set = subprocess.check_output(
                [is_root_set], cwd=self.debug_path, shell=True
            ).decode("utf-8")
            if ":!!:" in is_root_set.strip():
                # root pw was never set so return early, no need to change it
                root_change = (
                    f"Change_root_pass=False;last_root_changed=root_pass_never_set"
                )
                self.root_change_str = root_change
                return root_change
            root_test = subprocess.call(
                ["/bin/chage", "-l", "root"], cwd=self.debug_path
            )
            if root_test == 0:
                root_change = subprocess.check_output(
                    ["/bin/chage", "-l", "root"], cwd=self.debug_path
                ).decode("utf-8")
                root_change = str(root_change)
            regex = r"(\w{3})+\s+([0-9]{2})+\,+\s+([0-9]{4})|$"
            root_change = re.search(regex, root_change)
            root_change = root_change.group(0)
            root_change = datetime.strptime(root_change, "%b %d, %Y")
            today = datetime.now()
            root_change = str(root_change)
            root_change = root_change.replace("00:00:00", "")
            root_change = root_change.strip()
            if (root_change + str(timedelta(days=179))) <= str(today):
                root_change = f"Change_root_pass=False;last_root_changed={root_change}"
            else:
                root_change = f"Change_root_pass=True;last_root_changed={root_change}"
                self.root_change_bool = True
        except ValueError:
            root_change = "Change_root_pass=True;last_root_changed=False"
            self.root_change_bool = True
        self.root_change_str = root_change
        return root_change

    # Define the default messages
    def default_messages(self):
        osinfo = (
            f"RhelHostInfo_LastSent={self.date};OS={self.rhel};OS_Version={self.rhel_version};"
            f"OS_Name={self.rhel_name};OS_Release={self.rhel_release};)OS_Version_Date={self.rhel_version_date};"
            f"Platform_Type={self.machine};Processor_Type={self.processor};"
        )
        for proc in psutil.process_iter():
            process = proc.name().replace(" ", "")
            self.process_list.append(process)
        proc_list = "Host_Process_Names=" + " ".join(self.process_list)
        return osinfo + proc_list

    # Logs errors at the specified Severity Level
    def remote_notify(self, level=2, message=""):
        logging.config.fileConfig(self.syslog_path, disable_existing_loggers=False)
        # Define your own logger name
        logger = logging.getLogger(self.app_name)
        # Write messages with all different types of levels
        log_levels = {
            5 : logger.critical, 
            'CRITICAL' : logger.critical, 
            'critical' : logger.critical,
            4 : logger.error, 
            'ERROR' : logger.error, 
            'error' : logger.error,
            3 : logger.warning, 
            'WARNING' : logger.warning, 
            'warning' : logger.warning,
            2 : logger.info, 
            'INFO' : logger.info, 
            'info' : logger.info,
            1 : logger.debug, 
            'DEBUG' : logger.debug, 
            'debug' : logger.debug,
        }
        log_levels[level](message)


    def remote_notification(self):
        """calls all the RhelHostInfo methods in an appropriate order"""
        self.remote_notify(3, self.default_messages())
        self.remote_notify(3, self.accounts())
        self.remote_notify(3, self.inspect_accounts())
        self.remote_notify(3, self.interface_info())
        myapps = self.apps()
        self.remote_notify(3, myapps[0])
        self.remote_notify(3, myapps[1])
        self.remote_notify(3, myapps[2])
        self.remote_notify(3, myapps[3])
        self.remote_notify(3, self.time())
        self.remote_notify(3, self.ifaddrall())
        self.remote_notify(3, self.propinfo())
        self.remote_notify(3, self.hwinfo())
        self.remote_notify(3, self.sestatus())
        self.remote_notify(3, self.sudoers())
        self.remote_notify(3, self.root_change())

    def host_enumeration(self):
        """calls all the RhelHostInfo methods in an appropriate order"""
        self.default_messages()
        self.accounts()
        self.inspect_accounts()
        self.interface_info()
        self.apps()
        self.time()
        self.ifaddrall()
        self.propinfo()
        self.hwinfo()
        self.sestatus()
        self.sudoers()
        self.root_change()


# let's get all the info....
def main():
    host = RhelHostInfo()
    host.remote_notification()


if __name__ == "__main__":
    main()
