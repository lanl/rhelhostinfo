#!/bin/env python3

# external imports
import traceback
import argparse
import datetime
import rich
import rich.logging
import os
import sys
import logging
import logging.config
import logging.handlers
import configparser
from getpass import getuser
from cryptography.fernet import Fernet

# local imports
from app.state import State
from app.rhelhostinfo import RhelHostInfo
from app.rhelsknr import Scanner
from app.rhelsknr import Firewall
from app.rhelsknr import ImplementLynis
from app.openscap import ConfigHardening


class RhelSknr(State):
    """main application class"""

    def __init__(self):
        super().__init__()
        self.check_flag = False
        self.debug_flag = False
        self.everyday_flag = False
        self.generate_flag = False
        self.oscap_flag = False
        self.remediate_flag = False
        self.scan_flag = False
        self.verbose_flag = False
        self.extra_verbose_flag = False
        self.weekly_flag = False
        self.lynis_flag = False
        self.first_run_flag = False
        self.config = configparser.ConfigParser()
        self.scap = ConfigHardening()
        self.firewalld = Firewall()
        self.lynis = ImplementLynis()
        self.nmap = Scanner(timer_flag=False, timer_mins=15)
        self._key = bytes()
        self._fernet = bytes()
        self.rhelhostinfo = RhelHostInfo()
        self.config_path = f"{self.data_path}/{self.app_name}.ini"
        self.host_dict = dict()

    def notify(self, level=2, message=""):
        """
        Logs errors at the specified Severity Level
        """
        # if getattr(sys, 'frozen', False):
        # If the application is run as a bundle, the PyInstaller bootloader
        # extends the sys module by a flag frozen=True
        #    self.application_path = os.path.dirname(sys.executable)
        # else:
        application_path = os.path.dirname(os.path.abspath(__file__))
        # print("main application path", self.application_path)
        log_conf_path = f"{application_path}/app/log.conf"
        # print("main log path", self.log_path)
        self.message_count += 1
        logging.config.fileConfig(log_conf_path, disable_existing_loggers=False)
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

    def read_file(self):
        """
        read in a configparser object from configparser file
        """
        with open(self.config_path, "r") as read_file:
            plain_file = read_file.read()
        self.config.read_string(plain_file)
        return self.config

    def read_encrypted_file(self, file_name):
        """
        read in a Fermet encrypted file and decrypt it
        """
        with open(f"{self.application_path}/app/key.key", "rb") as key:
            self._key = key.read()
        self._fernet = Fernet(self._key)
        with open(file_name, "rb") as read_file:
            encrypted_file = read_file.read()
        plain_file = self._fernet.decrypt(encrypted_file)
        self.host_dict = plain_file
        return self.host_dict

    def read_file_into_message(self):
        """
        read in a file as a configparser object and then return it as a syslog message
        """
        self.read_file()
        for section in self.config.sections():
            for (key, val) in self.config.items(section):
                self.notify(2, f"{section}: {key}={val}")

    def write_file(self, data):
        """
        write configparser data to file
        """
        with open(
            os.open(self.config_path, os.O_CREAT | os.O_WRONLY, 0o600), "w"
        ) as config_file:
            data.write(config_file)

    def write_encrypted_file(self, file_name: str, data_dict):
        """
        encrypt and write a dictionary to a file

        """
        with open(f"{self.application_path}/app/key.key", "rb") as key:
            self._key = key.read()
        self._fernet = Fernet(self._key)
        with open(
            os.open(file_name, os.O_CREAT | os.O_WRONLY, 0o700), "wb"
        ) as config_file:
            encrypted_data = self._fernet.encrypt(data_dict)
            config_file.write(encrypted_data)

    def comparison(self):
        """module to provide historical comparison and changes via syslog"""
        old_host_config_flag = False
        if os.path.exists(self.config_path):
            old_host_config = self.read_file()
            old_host_config_flag = True
        self.rhelhostinfo.host_enumeration()
        new_hostconfig = configparser.ConfigParser()
        new_hostconfig["default_info"] = {}
        new_hostconfig["default_info"]["hostname"] = self.rhelhostinfo.hostname
        new_hostconfig["default_info"]["hostowner"] = self.rhelhostinfo.hostowner
        new_hostconfig["default_info"]["hwpropnum"] = self.rhelhostinfo.hwpropnum
        new_hostconfig["default_info"]["ipaddrpri"] = self.rhelhostinfo.ipaddrpri
        new_hostconfig["default_info"]["macaddrpri"] = self.rhelhostinfo.macaddr
        new_hostconfig["default_info"]["machine"] = self.rhelhostinfo.machine
        new_hostconfig["default_info"]["rhel"] = self.rhelhostinfo.rhel
        new_hostconfig["default_info"]["rhel_name"] = self.rhelhostinfo.rhel_name
        new_hostconfig["default_info"]["rhel_release"] = self.rhelhostinfo.rhel_release
        new_hostconfig["default_info"]["rhel_version"] = self.rhelhostinfo.rhel_version
        new_hostconfig["default_info"][
            "rhel_version_date"
        ] = self.rhelhostinfo.rhel_version_date
        new_hostconfig["default_info"]["root_change_bool"] = str(
            self.rhelhostinfo.root_change_bool
        )
        new_hostconfig["default_info"][
            "root_change_str"
        ] = self.rhelhostinfo.root_change_str
        new_hostconfig["default_info"]["processor"] = self.rhelhostinfo.processor
        new_hostconfig["SELinux"] = {}
        for index in range(0, len(self.rhelhostinfo.sestatus_list)):
            index = self.rhelhostinfo.sestatus_list[index].split("=")
            new_hostconfig["SELinux"][index[0]] = index[1]
        new_hostconfig["service_accounts"] = {}
        for index in range(0, len(self.rhelhostinfo.service_accounts)):
            new_hostconfig["service_accounts"][
                str(index)
            ] = self.rhelhostinfo.service_accounts[index]
        new_hostconfig["sudoers_list"] = {}
        for index in range(0, len(self.rhelhostinfo.sudoers_list)):
            new_val = self.rhelhostinfo.sudoers_list[index].strip()
            if new_val:
                if "%" in new_val:
                    new_val = new_val.replace("%", "%%")
                if "=" in new_val:
                    new_val = new_val.split("=")
                    new_hostconfig["sudoers_list"][new_val[0]] = new_val[1]
                else:
                    new_hostconfig["sudoers_list"][
                        str(index)
                    ] = self.rhelhostinfo.sudoers_list[index]
        new_hostconfig["user_accounts"] = {}
        for index in range(0, len(self.rhelhostinfo.user_accounts)):
            new_hostconfig["user_accounts"][
                str(index)
            ] = self.rhelhostinfo.user_accounts[index]
        new_hostconfig["hwinfo"] = {}
        for index in range(0, len(self.rhelhostinfo.hwinfo_list)):
            if self.rhelhostinfo.hwinfo_list[index].strip():
                hwinfo = self.rhelhostinfo.hwinfo_list[index].split("=")
                new_hostconfig["hwinfo"][hwinfo[0]] = hwinfo[1]
        new_hostconfig["all_interfaces"] = {}
        for index in range(0, len(self.rhelhostinfo.int_list)):
            interface = self.rhelhostinfo.int_list[index].split("=")
            new_hostconfig["all_interfaces"][interface[0]] = interface[1]
        new_hostconfig["macaddrs"] = {}
        for index in range(0, len(self.rhelhostinfo.macaddrs_list)):
            new_hostconfig["macaddrs"][str(index)] = self.rhelhostinfo.macaddrs_list[
                index
            ]
        new_hostconfig["time"] = {}
        for index in range(0, len(self.rhelhostinfo.time_list)):
            if ":" in self.rhelhostinfo.time_list[index]:
                continue
            my_time = self.rhelhostinfo.time_list[index].split("=")
            new_hostconfig["time"][my_time[0]] = my_time[1]
        new_hostconfig["local_accounts"] = {}
        for index in range(0, len(self.rhelhostinfo.non_org_users)):
            new_hostconfig["local_accounts"][
                str(index)
            ] = self.rhelhostinfo.non_org_users[index]
        new_hostconfig["current_network_processes"] = {}
        for index in range(0, len(self.rhelhostinfo.process_list)):
            new_hostconfig["current_network_processes"][
                str(index)
            ] = self.rhelhostinfo.process_list[index]
        new_hostconfig["root_change"] = {}
        change_list = self.rhelhostinfo.root_change_str.split(";")
        for index in range(0, len(change_list)):
            line = change_list[index].split("=")
            new_hostconfig["root_change"][line[0]] = line[1]
        new_hostconfig["installed_applications"] = {}
        for index in range(0, len(self.rhelhostinfo.apps_list)):
            application = self.rhelhostinfo.apps_list[index].split(",")
            if application[0].strip():
                # have to standardize the output
                if len(application) == 1:
                    new_hostconfig["installed_applications"][
                        application[0]
                    ] = f"None:None"
                elif len(application) == 2:
                    new_hostconfig["installed_applications"][
                        application[0]
                    ] = f"{application[1]}:None"
                else:
                    new_hostconfig["installed_applications"][
                        application[0]
                    ] = f"{application[1]}:{application[2]}"
        new_hostconfig["interfaces"] = {}
        for index in range(0, len(self.rhelhostinfo.interfaces)):
            new_hostconfig["interfaces"][str(index)] = self.rhelhostinfo.interfaces[
                index
            ]
        old_set = set()
        new_set = set()
        old_processes = set()
        new_processes = set()
        new_service_accounts = set()
        old_service_accounts = set()
        new_applications = set()
        old_applications = set()
        new_user_accounts = set()
        old_user_accounts = set()
        new_local_accounts = set()
        old_local_accounts = set()
        new_macaddrs = set()
        old_macaddrs = set()
        new_interfaces = set()
        old_interfaces = set()
        if old_host_config_flag:
            old_list = old_host_config.sections()
            for old_section in old_list:
                if "current_network_processes" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_processes.add(old_val)
                elif "service_accounts" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_service_accounts.add(old_val)
                elif "installed_applications" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_applications.add(f"{old_key}={old_val}")
                elif "user_accounts" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_user_accounts.add(f"{old_val}")
                elif "local_accounts" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_local_accounts.add(f"{old_val}")
                elif "macaddrs" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_macaddrs.add(f"{old_key}={old_val}")
                elif "interfaces" == old_section:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        old_interfaces.add(f"{old_key}={old_val}")
                else:
                    for (old_key, old_val) in old_host_config.items(old_section):
                        line = f"{old_key}={old_val}"
                        old_set.add(line)
            new_list = new_hostconfig.sections()
            for section in new_list:
                if "current_network_processes" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_processes.add(val)
                elif "service_accounts" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_service_accounts.add(val)
                elif "installed_applications" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_applications.add(f"{key}={val}")
                elif "user_accounts" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_user_accounts.add(f"{val}")
                elif "local_accounts" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_local_accounts.add(f"{val}")
                elif "macaddrs" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_macaddrs.add(f"{key}={val}")
                elif "interfaces" == section:
                    for (key, val) in new_hostconfig.items(section):
                        new_interfaces.add(f"{key}={val}")
                else:
                    for (key, val) in new_hostconfig.items(section):
                        line = f"{key}={val}"
                        new_set.add(line)
            # compare the old with the new to identify any changes that occurred
            adds = list()
            drops = list()
            for line in old_set:
                if line not in new_set:
                    drops.append(line)
            for line in new_set:
                if line not in old_set:
                    adds.append(line)
            # break out the process comparison separately because we want to compare just values, not the lines that
            # are in key=value format
            # also remove the kworker processes because they add a lot of noise without a lot of significant value
            for val in old_processes:
                if val not in new_processes and "kworker" not in val:
                    drops.append("process: " + val)
            for val in new_processes:
                if val not in old_processes and "kworker" not in val:
                    adds.append("process: " + val)
            for val in old_service_accounts:
                if val not in new_service_accounts:
                    drops.append("service_account: " + val)
            for val in new_service_accounts:
                if val not in old_service_accounts:
                    adds.append("service_account: " + val)
            for val in old_applications:
                if val not in new_applications:
                    drops.append("application: " + val)
            for val in new_applications:
                if val not in old_applications:
                    adds.append("application: " + val)
            for val in old_user_accounts:
                if val not in new_user_accounts:
                    drops.append("user: " + val)
            for val in new_user_accounts:
                if val not in old_user_accounts:
                    adds.append("user: " + val)
            for val in old_local_accounts:
                if val not in new_local_accounts:
                    drops.append("local_account: " + val)
            for val in new_local_accounts:
                if val not in old_local_accounts:
                    adds.append("local_account: " + val)
            for val in old_macaddrs:
                if val not in new_macaddrs:
                    drops.append("macaddr: " + val)
            for val in new_macaddrs:
                if val not in old_macaddrs:
                    adds.append("macaddr: " + val)
            for val in old_interfaces:
                if val not in new_interfaces:
                    drops.append("interface: " + val)
            for val in new_interfaces:
                if val not in old_interfaces:
                    adds.append("interface: " + val)
            if adds and drops:
                message_str = (
                    f"{self.hostname} reports config_changes=True; adds=({', '.join(adds)}); "
                    f"drops=({', '.join(drops)})"
                )
                self.notify(3, message_str)
                os.remove(self.config_path)
                self.write_file(new_hostconfig)
            elif adds and not drops:
                message_str = (
                    f"{self.hostname} reports config_changes=True; adds=({', '.join(adds)}); "
                    f"drops=None"
                )
                self.notify(3, message_str)
                os.remove(self.config_path)
                self.write_file(new_hostconfig)
            elif drops and not adds:
                message_str = (
                    f"{self.hostname} reports config_changes=True; adds=None; "
                    f"drops=({', '.join(drops)})"
                )
                self.notify(3, message_str)
                os.remove(self.config_path)
                self.write_file(new_hostconfig)
            else:
                message_str = f"{self.hostname} reports config_changes=False"
                self.notify(3, message_str)
        else:
            self.write_file(new_hostconfig)
            self.notify(3, f"{self.hostname} wrote initial changes to file.")
            for section in new_hostconfig.sections():
                options_list = new_hostconfig.items(section)
                msg = f"{section}: "
                for my_tuple in options_list:
                    my_str = str(my_tuple)[1:-1] + ","
                    msg += my_str
                self.notify(3, msg)

    def app_start(self):
        """Identifies application initialization"""
        message = f"Starting={self.app_name}, start_time={self.start_time}."
        self.notify(level=3, message=message)

    def app_end(self):
        """Identifies application completion"""
        end_time = datetime.datetime.today()
        runtime = end_time - self.start_time
        message = (
            f"Ending={self.app_name}, total_message_count={self.message_count}, "
            f"end_time={end_time}, run_time={runtime}."
        )
        self.notify(level=3, message=message)

    def full_configuration_report(self):
        """Fully report the rhelhostinfo security-relevant config data,
        this could be done on a weekly or even monthly basis"""
        self.notify(3, self.rhelhostinfo.default_messages())
        self.notify(3, self.rhelhostinfo.accounts())
        self.notify(3, self.rhelhostinfo.inspect_accounts())
        self.notify(3, self.rhelhostinfo.interface_info())
        myapps = self.rhelhostinfo.apps()
        self.notify(3, myapps[0])
        self.notify(3, myapps[1])
        self.notify(3, myapps[2])
        self.notify(3, myapps[3])
        self.notify(3, self.rhelhostinfo.time())
        self.notify(3, self.rhelhostinfo.ifaddrall())
        self.notify(3, self.rhelhostinfo.propinfo())
        self.notify(3, self.rhelhostinfo.hwinfo())
        self.notify(3, self.rhelhostinfo.sestatus())
        self.notify(3, self.rhelhostinfo.sudoers())
        self.notify(3, self.rhelhostinfo.root_change())

    def parser(self):
        """module to provide commandline options for the application"""
        parser = argparse.ArgumentParser(
            description=f"RhelHostInfo v{self.maj_version}.{self.min_version} provides "
            f"cybersecurity / host monitoring functionality for detection of "
            f"configuration vulnerabilities, remediation, identification of "
            f"host changes and user activity.",
            prog=f"rhelhostinfo",
            usage="%(prog)s [options]",
        )

        parser.add_argument(
            "-c",
            "--checkconfig",
            action="store_true",
            default="",
            dest="check",
            help="Check the local host for configuration changes",
        )

        parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            dest="debug",
            help="Debug granularity for application troubleshooting",
        )

        parser.add_argument(
            "-e",
            "--everyday",
            action="store_true",
            dest="everyday",
            help="Actions to conduct every day",
        )

        parser.add_argument(
            "-g",
            "--generate",
            action="store_true",
            dest="generate",
            help="Generate oscap remediation script",
        )

        parser.add_argument(
            "-l",
            "--lynis",
            action="store_true",
            default="",
            dest="lynis",
            help="Implement Lynis system configuration checks",
        )

        parser.add_argument(
            "-o",
            "--oscap",
            action="store_true",
            dest="oscap",
            help="Report the oscap findings for the host and view html report",
        )

        parser.add_argument(
            "-r",
            "--remediate",
            action="store_true",
            default="",
            dest="remediate",
            help="Remediate the host to comply with STIG content",
        )

        parser.add_argument(
            "-s",
            "--scan",
            action="store_true",
            default="",
            dest="scan",
            help="Scan the local network",
        )

        parser.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=0,
            dest="verbose",
            help="Add verbose output to console.",
        )

        parser.add_argument(
            "-w",
            "--weekly",
            action="store_true",
            default="",
            dest="weekly",
            help="Weekly enumeration of host information",
        )

        try:
            args = parser.parse_args()

            # set arg flags
            if args.check:
                self.check_flag = True
            if args.debug:
                self.debug_flag = True
            if args.everyday:
                self.everyday_flag = True
            if args.generate:
                self.generate_flag = True
            if args.oscap:
                self.oscap_flag = True
            if args.remediate:
                self.remediate_flag = True
            if args.scan:
                self.scan_flag = True
            if args.verbose:
                self.verbose_flag = True
            if args.weekly:
                self.weekly_flag = True
            if args.lynis:
                self.lynis_flag = True

        except SystemExit:
            pass

    def tailor(self):
        """
        Determine what parsing options match what application functionality.
        Separated from the parser functionality to make it easier to read / change to fit organizational needs.
        """
        if self.check_flag:
            state, difference = self.firewalld.firewall(full_firewall_data=False)
            self.notify(3, f"{state}; {difference}")
            self.comparison()
        if self.debug_flag:
            self.notify(2, "[**] functionality not implemented, need to add...")
            pass
        if self.everyday_flag:
            state, difference = self.firewalld.firewall(full_firewall_data=False)
            self.notify(3, f"{state}; {difference}")
            self.comparison()
        if self.generate_flag:
            self.notify(3, self.scap.generate_remediation_script())
        if self.oscap_flag:
            self.notify(3, self.scap.rhel_sw_vulns())
            self.notify(3, "".join(self.scap.report_tailoring()))
            self.notify(3, self.scap.oscap_report())
            self.scap.oscap_view()
        if self.remediate_flag:
            self.notify(3, self.scap.oscap_remediate())
            self.notify(3, "".join(self.scap.report_tailoring()))
        if self.scan_flag:
            self.notify(
                3,
                self.nmap.pick_scan(
                    scan_type="os",
                    scan_report="custom",
                    subnet_int=29,
                    randomize_bool=False,
                    full_report_flag=False,
                ),
            )
        if self.verbose_flag:
            self.notify(2, "[**] functionality not implemented, need to add...")
            pass
        if self.weekly_flag:
            self.full_configuration_report()
            state, difference = self.firewalld.firewall(full_firewall_data=True)
            self.notify(3, f"{state}; {difference}")
            self.scap.rhel_sw_vulns()
            self.notify(3, "".join(self.scap.report_tailoring()))
            self.notify(
                3,
                self.nmap.pick_scan(
                    scan_type="os",
                    scan_report="custom",
                    subnet_int=29,
                    randomize_bool=False,
                    full_report_flag=True,
                ),
            )
            #self.notify(3, self.scap.oscap_report())
            #self.notify(3, self.scap.oscap_remediate())
        if self.lynis_flag:
            # this could be added to the everyday / weekly options if desired
            self.notify(3, self.lynis.run_lynis(full_lynis_flag=False))


def main():
    try:
        rhel = RhelSknr()
        rhel.app_start()
        rhel.parser()
        rhel.tailor()
        rhel.app_end()
    except PermissionError as error:
        error = traceback.format_exc()
        error = str(error.strip())
        error = error.replace("\t", "")
        error = error.replace("  ", "")
        error += "\n"
        sys.stderr.write(error)
        console = rich.console.Console()
        message = f"[**] ERROR: running application as {getuser()}, try again as root."
        console.print(message, style="bold red")
        message += "\n"
        sys.stderr.write(message)
    except:
        error = traceback.format_exc()
        error = str(error.strip())
        error = error.replace("\t", "")
        error = error.replace("  ", "")
        error += "\n"
        sys.stderr.write(error)


if __name__ == "__main__":
    main()
