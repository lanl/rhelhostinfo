#!/usr/bin/env python3

##################################################################################
#
# Written by Skip McGee 03/2021
#
# rhelsknr is designed to run as a modern python (3.9+) utility to provide
# active and passive security-relevant configuration data to security analysts
# for monitoring and review in a SIEM such as Splunk.
# The nmap-based scanner provides a variety of scan options to identify what
# OSs, services and ports are open on your network.
# The provided firewalld module enumerates the firewalld state and rules.
# Lynis is used as an easily available yum install tool available in the
# standard RedHat repos to conduct system configuration auditing.
#
# Endstate: run the active detection shooting match on a couple of hosts 
# per subnet on a weekly basis. (or more, or more frequently!)
#
# Gain detection capability and visibility into management networks
# and other weird corners of your environment.....
#
# Build some cool SEIM / splunk dashboards and increase your awareness of the 
# vulnerabilities and changes in your environment!
#
##################################################################################

# initial module imports
import subprocess
import configparser
import json
import psutil
import socket
import nmap3
import time
import random
import difflib
import shutil
import re
import os
from deepdiff import DeepDiff
from json2xml import json2xml
from json2xml.utils import readfromstring
# xmldiff commented out until the error with it and pyinstaller can be addressed
# see the xml reports method for more detail
# from xmldiff import main as mn
# from xmldiff import formatting
import pyndiff
from lxml import etree

# internal imports
from app.state import State


# Define the Scanner class
class Scanner(State):
    def __init__(self, timer_flag: bool = False, timer_mins: int = 15):
        super().__init__()
        """ 
        Define the local network scanner and conduct a scan. 
        """
        self.nmap = nmap3.Nmap()
        self.nmap_techniques = nmap3.NmapScanTechniques()
        self.ip_and_subnet = str()
        self.iplist = list()
        self.iplist_6 = list()
        self.timer_delay = timer_mins
        self.timer_flag = timer_flag
        self.check_network = list()
        self.scanner_flag = False
        self.os_flag = False
        self.version_flag = False
        self.fin_flag = False
        self.idle_flag = False
        self.ping_flag = True
        self.syn_flag = False
        self.udp_flag = False
        self.tcp_flag = False
        self.os_scan_dict = dict()
        self.recent_scan_filename_list = list()
        self.version_scan_dict = dict()
        self.fin_scan_dict = dict()
        self.idle_scan_dict = dict()
        self.ping_scan_dict = dict()
        self.syn_scan_dict = dict()
        self.udp_scan_dict = dict()
        self.tcp_scan_dict = dict()
        self.scan_results_dict = {
            "idle": self.idle_scan_dict,
            "os": self.os_scan_dict,
            "version": self.version_scan_dict,
            "fin": self.fin_scan_dict,
            "ping": self.ping_scan_dict,
            "syn": self.syn_scan_dict,
            "udp": self.udp_scan_dict,
            "tcp": self.tcp_scan_dict,
        }
        self.os_scan_filename = self.data_path + "/" + "os_scan"
        self.os_scan_filename_index = self.os_scan_filename + "_file_index.txt"
        self.version_scan_filename = self.data_path + "/" + "version_scan"
        self.version_scan_filename_index = self.version_scan_filename + "_file_index.txt"
        self.fin_scan_filename = self.data_path + "/" + "fin_scan"
        self.fin_scan_filename_index = self.fin_scan_filename + "_file_index.txt"
        self.idle_scan_filename = self.data_path + "/" + "idle_scan"
        self.idle_scan_filename_index = self.idle_scan_filename + "_file_index.txt"
        self.ping_scan_filename = self.data_path + "/" + "ping_scan"
        self.ping_scan_filename_index = self.ping_scan_filename + "_file_index.txt"
        self.syn_scan_filename = self.data_path + "/" + "syn_scan"
        self.syn_scan_filename_index = self.syn_scan_filename + "_file_index.txt"
        self.udp_scan_filename = self.data_path + "/" + "udp_scan"
        self.udp_scan_filename_index = self.udp_scan_filename + "_file_index.txt"
        self.tcp_scan_filename = self.data_path + "/" + "tcp_scan"
        self.tcp_scan_filename_index = self.tcp_scan_filename + "_file_index.txt"
        self.current_scan_filename = str()
        self.report_types_list = ["xml", "json", "custom"]
        self.scan_options_dict = {
            "idle": self.idle_scan,
            "os": self.os_scan,
            "version": self.version_scan,
            "fin": self.fin_scan,
            "ping": self.ping_scan,
            "syn": self.syn_scan,
            "udp": self.udp_scan,
            "tcp": self.tcp_scan,
        }
        self.scan_filenames_dict = {
            "idle": self.idle_scan_filename,
            "os": self.os_scan_filename,
            "version": self.version_scan_filename,
            "fin": self.fin_scan_filename,
            "ping": self.ping_scan_filename,
            "syn": self.syn_scan_filename,
            "udp": self.udp_scan_filename,
            "tcp": self.tcp_scan_filename,
        }

        # Define the host's active interfaces / ips
        for interface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                # for now, only ipv4 compatibility
                if snic.family == socket.AF_INET:
                    self.iplist.append(snic.address)
                # ipv6 compatibility in future
                elif snic.family == socket.AF_INET6:
                    self.iplist_6.append(snic.address)

        # Delay based on random values over a user-input time interval to prevent congestion from multiple
        # hosts on a subnet scanning at once
        if timer_flag:
            self.delay_timer(self.timer_delay)

    def delay_timer(self, delay_in_mins: int):
        """
        delay script running to deconflict network congestion in case multiple hosts are running scans
        at the same time
        """
        print("[***] Scanner: starting timer....")
        secs = delay_in_mins * 60
        time.sleep(random.randint(1, secs))
        print("[***] Scanner: ending timer!")

    def install_nmap(self):
        """
        yum install nmap if not installed
        """
        nmap_installed = subprocess.call(["rpm -q nmap"], shell=True)
        if nmap_installed != 0:
            try:
                subprocess.call(["yum install -y nmap"], shell=True)
            except Exception as error:
                print(f"[**] Scanner: yum install of nmap failed, {error}")

    def check_list(self, subnet: int = 24, randomize_scan: bool = False) -> list:
        """
        We need to define the list of IPv4 IPs that we want to check for every interface with an IP
        For ease of calculation, we will do this for a /24 by default in a randomized scan
        ** IPv6 parsing would be a good future addition to this method **
        """
        if randomize_scan:
            for ip in self.iplist:
                # let's double check for / ignore localhost addressing
                if "127.0.0.1" in str(ip):
                    continue
                self.ip_and_subnet = ip + "/" + str(subnet)
                # remove last octet because we are only replacing this /24
                address = ip.split(".")
                # double check for ipv4 formatted addresses
                if len(address) != 4:
                    continue
                network_address = address[0:3]
                host_address = address[3]
                network_address = ".".join(network_address)
                # add all values from 1-255 except the ip itself to check_network
                for integer in range(1, 256):
                    if str(integer) == host_address:
                        continue
                    else:
                        # note that we aren't using a subnet here because we are randomizing all the addresses inside
                        # the /24 subnet. This will return a different formatted scan than the subnet scan, so it will
                        # be important to standardize scripting based on one or the other format to dial in parsing
                        test_address = network_address + "." + str(integer)
                        self.check_network.append(test_address)
                random.shuffle(self.check_network)
        else:
            for ip in self.iplist:
                # let's double check for / ignore localhost addressing
                if "127.0.0.1" in str(ip):
                    continue
                else:
                    self.ip_and_subnet = ip + "/" + str(subnet)
                    self.check_network.append(self.ip_and_subnet)
        print(f"[**] Scanner: found the following IP(s) to scan {self.check_network}.")
        return self.check_network

    def write_json_to_file(self, file_name: str, scan_dict: dict):
        """easy method to write a list of dicts to a file as json """
        if os.path.exists(file_name):
            shutil.copy(file_name, f"{file_name}.old")
        with open(os.open(file_name, os.O_CREAT | os.O_WRONLY, 0o600), "w+") as outfile:
            json.dump(scan_dict, outfile)

    def write_json_to_file_as_str(self, file_name: str, scan_dict: dict):
        """easy method to write a list of dicts to a file as a json string"""
        if os.path.exists(file_name):
            shutil.copy(file_name, f"{file_name}.old")
        with open(os.open(file_name, os.O_CREAT | os.O_WRONLY, 0o600), "w+") as outfile:
            json_data = json.dumps(scan_dict, skipkeys=True)
            outfile.write(json_data)

    def read_json_from_file(self, filename: str):
        """easy method to read in a json file and return a python data type"""
        if not os.path.exists(filename):
            raise FileNotFoundError
        with open(filename, 'r') as json_file:
            python_data = json.load(json_file)
        return python_data

    def os_scan(self, check_list: list) -> dict:
        """
        conduct an os scan using the ip list provided
        """
        for ip in check_list:
            os_result = self.nmap.nmap_os_detection(ip)
            # let's not get bogged
            # down in hosts that aren't up
            if os_result and not "(0 hosts up)" in str(os_result):
                print("Scanner: ", os_result)
                self.os_scan_dict[ip] = {}
                self.os_scan_dict[ip] = os_result
                formatted_ip = ip.replace("/", "-")
                self.current_scan_filename = self.os_scan_filename + f"_{formatted_ip}_" + ".json"
                if os.path.exists(self.current_scan_filename):
                    shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
                self.recent_scan_filename_list.append(self.current_scan_filename)
                self.write_json_to_file_as_str(self.current_scan_filename, os_result)
        if os.path.exists(self.os_scan_filename_index):
            shutil.copy(self.os_scan_filename_index, self.os_scan_filename_index + ".old")
        with open(self.os_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name+"\n")
        return self.os_scan_dict

    def version_scan(self, check_list: list) -> dict:
        """
        conduct a version scan using the ip list provided
        """
        self.version_scan_filename = self.version_scan_filename
        for ip in check_list:
            version_result = self.nmap.nmap_version_detection(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(version_result):
                continue
            print("Scanner: ", version_result)
            self.version_scan_dict[ip] = {}
            self.version_scan_dict[ip] = version_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.version_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, version_result)
        if os.path.exists(self.version_scan_filename_index):
            shutil.copy(self.version_scan_filename_index, self.version_scan_filename_index + ".old")
        with open(self.version_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.version_scan_dict

    def fin_scan(self, check_list: list) -> dict:
        """
        conduct a fin scan using the ip list provided
        """
        self.current_scan_filename = self.fin_scan_filename
        for ip in check_list:
            fin_result = self.nmap_techniques.nmap_fin_scan(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(fin_result):
                continue
            print("Scanner: ", fin_result)
            self.fin_scan_dict[ip] = {}
            self.fin_scan_dict[ip] = fin_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.fin_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, fin_result)
        if os.path.exists(self.fin_scan_filename_index):
            shutil.copy(self.fin_scan_filename_index, self.fin_scan_filename_index + ".old")
        with open(self.fin_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.fin_scan_dict

    def idle_scan(self, check_list: list) -> dict:
        """
        conduct an idle scan using the ip list provided
        """
        self.current_scan_filename = self.idle_scan_filename
        for ip in check_list:
            idle_result = self.nmap_techniques.nmap_idle_scan(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(idle_result):
                continue
            print("Scanner: ", idle_result)
            self.idle_scan_dict[ip] = {}
            self.idle_scan_dict[ip] = idle_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.idle_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, idle_result)
        if os.path.exists(self.idle_scan_filename_index):
            shutil.copy(self.idle_scan_filename_index, self.idle_scan_filename_index + ".old")
        with open(self.idle_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.idle_scan_dict

    def ping_scan(self, check_list: list) -> dict:
        """
        conduct a ping scan using the ip list provided
        """
        self.current_scan_filename = self.ping_scan_filename
        for ip in check_list:
            ping_result = self.nmap_techniques.nmap_ping_scan(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(ping_result):
                continue
            print("Scanner: ", ping_result)
            self.ping_scan_dict[ip] = {}
            self.ping_scan_dict[ip] = ping_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.ping_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, ping_result)
        if os.path.exists(self.ping_scan_filename_index):
            shutil.copy(self.ping_scan_filename_index, self.ping_scan_filename_index + ".old")
        with open(self.ping_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.ping_scan_dict

    def syn_scan(self, check_list: list) -> dict:
        """
        conduct a syn scan using the ip list provided
        same as 'Nmap -sS -p1-65535 tcp.xml network/24'
        """
        self.current_scan_filename = self.syn_scan_filename
        for ip in check_list:
            syn_result = self.nmap_techniques.nmap_syn_scan(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(syn_result):
                continue
            print("Scanner: ", syn_result)
            self.syn_scan_dict[ip] = {}
            self.syn_scan_dict[ip] = syn_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.syn_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, syn_result)
        if os.path.exists(self.syn_scan_filename_index):
            shutil.copy(self.syn_scan_filename_index, self.syn_scan_filename_index + ".old")
        with open(self.syn_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.syn_scan_dict

    def udp_scan(self, check_list: list) -> dict:
        """
        conduct a udp scan using the ip list provided
        same as 'Nmap -sU -p1-65535 udp.xml network/24'
        """
        self.current_scan_filename = self.udp_scan_filename
        for ip in check_list:
            udp_result = self.nmap_techniques.nmap_udp_scan(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(udp_result):
                continue
            print("Scanner: ", udp_result)
            self.udp_scan_dict[ip] = {}
            self.udp_scan_dict[ip] = udp_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.udp_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, udp_result)
        if os.path.exists(self.udp_scan_filename_index):
            shutil.copy(self.udp_scan_filename_index, self.udp_scan_filename_index + ".old")
        with open(self.udp_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.udp_scan_dict

    def tcp_scan(self, check_list: list) -> dict:
        """
        conduct a tcp scan using the ip list provided
        same as 'Nmap -sT -p1-65535 tcp.xml network/24' in regular nmap
        """
        self.current_scan_filename = self.tcp_scan_filename
        for ip in check_list:
            tcp_result = self.nmap_techniques.nmap_tcp_scan(ip)
            # let's not get bogged down in hosts that aren't up
            if "(0 hosts up)" in str(tcp_result):
                continue
            print("Scanner: ", tcp_result)
            self.tcp_scan_dict[ip] = {}
            self.tcp_scan_dict[ip] = tcp_result
            formatted_ip = ip.replace("/", "-")
            self.current_scan_filename = self.tcp_scan_filename + f"_{formatted_ip}_" + ".json"
            if os.path.exists(self.current_scan_filename):
                shutil.copy(self.current_scan_filename, self.current_scan_filename + ".old")
            self.recent_scan_filename_list.append(self.current_scan_filename)
            self.write_json_to_file_as_str(self.current_scan_filename, tcp_result)
        if os.path.exists(self.tcp_scan_filename_index):
            shutil.copy(self.tcp_scan_filename_index, self.tcp_scan_filename_index + ".old")
        with open(self.tcp_scan_filename_index, "w+") as outfile:
            for file_name in self.recent_scan_filename_list:
                outfile.write(file_name + "\n")
        return self.tcp_scan_dict

    def json_reports(self, file_name: str, full_report_flag: bool = False):
        """
        parse the scan output for changes, use the native dict/json formatting to identify changes
        """
        new_file_name = file_name
        old_file_name = file_name + ".old"
        if full_report_flag or not os.path.exists(old_file_name):
            print("[**] Scanner: returning full data as a string.")
            data = self.read_json_from_file(new_file_name)
            return data
        else:
            new_file = self.read_json_from_file(new_file_name)
            old_file = self.read_json_from_file(old_file_name)
            result = DeepDiff(new_file, old_file)
            if not result:
                result = "[**] Scanner: no changes to local network."
            # add some formatting for better message parsing?
            for line in result:
                print(line)
            return result

    def convert_json_to_xml(self, file_name: str):
        """
        write our python nmap files to xml to use a different comparison tool
        """
        new_file_name = file_name
        old_file_name = file_name + ".old"
        if os.path.exists(new_file_name):
            new_xml_str = self.read_json_from_file(new_file_name)
            new_xml_str = readfromstring(new_xml_str)
            new_xml = json2xml.Json2xml(new_xml_str).to_xml()
            with open(os.open(new_file_name + ".xml", os.O_CREAT | os.O_WRONLY, 0o600), "w") as new_xml_file:
                new_xml_file.write(new_xml)
        else:
            print(f"[**] Scanner: new file path {new_file_name} does not exist.")
        if os.path.exists(old_file_name):
            old_xml_str = self.read_json_from_file(old_file_name)
            old_xml_str = readfromstring(old_xml_str)
            old_xml = json2xml.Json2xml(old_xml_str).to_xml()
            with open(os.open(old_file_name + ".xml", os.O_CREAT | os.O_WRONLY, 0o600), "w") as old_xml_file:
                old_xml_file.write(old_xml)
        else:
            print(f"[**] Scanner: old file path {old_file_name} does not exist.")

    def xml_reports(self, file_name: str, full_report_flag: bool = False):
        """
        parse the scan output for local environment changes, convert to xml
        alas the formatting of the python nmap module doesn't appear to work with pyndiff
        so we will use xmldiff here
        """
        # issue with this method identified below, I tried to implement a hook without success
        """
            from xmldiff import main as mn
          File "<frozen importlib._bootstrap>", line 1058, in _handle_fromlist
          File "<frozen importlib._bootstrap>", line 228, in _call_with_frames_removed
          File "<frozen importlib._bootstrap>", line 1007, in _find_and_load
          File "<frozen importlib._bootstrap>", line 986, in _find_and_load_unlocked
          File "<frozen importlib._bootstrap>", line 680, in _load_unlocked
          File "PyInstaller/loader/pyimod03_importers.py", line 495, in exec_module
          File "xmldiff/main.py", line 9, in <module>
          File "pkg_resources/__init__.py", line 897, in require
          File "pkg_resources/__init__.py", line 783, in resolve
        pkg_resources.DistributionNotFound: The 'six' distribution was not found and is required by xmldiff
        """
        new_file_name = file_name
        old_file_name = file_name + ".old"
        if (full_report_flag or not os.path.exists(old_file_name)) and os.path.exists(
            new_file_name
        ):
            print("[**] Scanner: returning full data as a string.")
            data = self.read_json_from_file(new_file_name)
            return data
        else:
            self.convert_json_to_xml(file_name)
            new_file_name += ".xml"
            old_file_name += ".xml"
            # this xml diff call can take a while
            print("[**] Scanner: returning xmldiff data from previous report.")
            diff = mn.diff_files(
                new_file_name, old_file_name, formatter=formatting.XMLFormatter()
            )
            # need to troubleshoot integration with this pyndiff library, currently tries to load the first file and
            # returns an exception of None
            # diff = pyndiff.generate_diff(new_file_name, old_file_name, ignore_udp_open_filtered=False,
            # output_type="txt")
            diff_list = list()
            diff = diff.split("\n")
            for line in diff:
                if "diff:" in line:
                    if 'diff:delete=""' not in line:
                        diff_list.append(line.strip())
            if not diff_list:
                diff = "[**] Scanner: no changes to local network."
            else:
                diff = "; ".join(diff_list)
            print(diff)
            return diff

    def custom_report(
        self,
        index_file_name: str = "/opt/rhelhostinfo/data/os_scan_file_index.txt",
        scan_type: str = "os",
        full_report_flag: bool = False,
    ) -> str:
        """
        Custom parsing for comparison of the previous / current basic scans as dicts, may need modification to
        work with other types of scans. Returns a string in json-like formatting for easy syslog message ingestion.
        """
        adds_dict = dict()
        compare_dict = dict()
        drops_dict = dict()
        old_dict = dict()
        old_index_list = list()
        adds_list = list()
        drops_list = list()
        old_index_file_name = index_file_name + ".old"
        if full_report_flag or not os.path.exists(old_index_file_name):
            # simply return the current scan for the designated scan type
            print(f"[**] Scanner: returning last '{scan_type}' scan data as a string.")
            return str(self.scan_results_dict[scan_type])
        else:
            # start by comparing the current scan subnets to the previous scan subnets to identify any differences
            print(
                f"[**] Scanner: parsing '{scan_type}' scan to identify differences between current and previous scan."
            )
            try:
                with open(old_index_file_name, "r") as old_file:
                    for file_name in old_file.readlines():
                        subnet = str(file_name).strip().split("_")[-2]
                        subnet = subnet.replace("-", "/")
                        old_index_list.append(subnet)
                        if subnet not in self.check_network:
                            drops_list.append(subnet)
                        else:
                            old_dict[subnet] = self.read_json_from_file(file_name.strip() + ".old")
                for subnet in self.check_network:
                    if subnet not in old_index_list:
                        adds_list.append(subnet)
                        #adds_dict[subnet] = self.read_json_from_file(file_name)
                    else:
                        compare_dict[subnet] = self.scan_results_dict[scan_type][subnet]
                if adds_list:
                    adds_str = ' '.join(adds_list)
                    print(
                        f"[**] Scanner: added subnet(s) {adds_str}."
                    )
                    drops_dict['added_subnets'] = adds_str
                if drops_list:
                    drops_str = ' '.join(drops_list)
                    print(
                        f"[**] Scanner: removed subnet(s) {drops_str}."
                    )
                    drops_dict['removed_subnets'] = drops_str
            except Exception as err:
                print(
                    f"[**] Scanner: Error with initial file comparison:"
                )
                print(err)
                return str(self.scan_results_dict[scan_type])
            # Now we have identified the subnet changes between the last scan and the recent scan
            # These changes should happen infrequently but we care about knowing that they happened vs the old data
            # we have 2 dicts that we can parse / compare for relevant scan changes: compare_dict and old_dict
            try:
                for ip_range in self.check_network:
                    for ip in old_dict[ip_range]:
                        if "." not in ip:
                            continue
                        if str(ip) not in str(compare_dict[ip_range]):
                            # ip doesn't exist so add the whole thing
                            drops_dict[ip_range] = dict()
                            drops_dict[ip_range][ip] = old_dict[ip_range][ip]
                        else:
                            for section in old_dict[ip_range][ip]:
                                if "stats" in section or "runtime" in section:
                                    continue
                                if not old_dict[ip_range][ip][section]:
                                    continue
                                if "osmatch" in section:
                                    # special logic due to the dictionaries nested in a list in the osmatch section with the
                                    # first dictionary being the most likely one to match the host
                                    if old_dict[ip_range][ip]['osmatch'][0]['name'] not in compare_dict[ip_range][ip]['osmatch'][0]['name']:
                                        if str(ip) not in drops_dict:
                                            drops_dict[ip_range] = dict()
                                            drops_dict[ip_range][ip] = dict()
                                        drops_dict[ip_range][ip][section] = old_dict[ip_range][ip][
                                            section][0]
                                else:
                                    if str(old_dict[ip_range][ip][section]) not in str(
                                            compare_dict[ip_range][ip][section]):
                                        if "dict" in str(type(compare_dict[ip_range][ip][section])):
                                            for key, val in old_dict[ip_range][ip][section].items():
                                                if str(val) not in str(
                                                        compare_dict[ip_range][ip][section].values()):
                                                    if str(val).strip():
                                                        if str(ip) not in drops_dict:
                                                            drops_dict[ip_range] = dict()
                                                            drops_dict[ip_range][ip] = dict()
                                                        drops_dict[ip_range][ip][section] = dict()
                                                        drops_dict[ip_range][ip][section][key] = val
                                        elif "list" in str(type(compare_dict[ip_range][ip][section])):
                                            for subsection in range(len(old_dict[ip_range][ip][section])):
                                                if str(old_dict[ip_range][ip][section][
                                                           subsection]) not in str(
                                                        compare_dict[ip_range][ip][section]):
                                                    if str(old_dict[ip_range][ip][section][
                                                               subsection]).strip():
                                                        if str(ip) not in drops_dict:
                                                            drops_dict[ip_range] = dict()
                                                            drops_dict[ip_range][ip] = dict()
                                                        drops_dict[ip_range][ip][section] = \
                                                        old_dict[ip_range][ip][section][subsection]
                                        else:
                                            if str(ip) not in drops_dict:
                                                drops_dict[ip_range] = dict()
                                                drops_dict[ip_range][ip] = dict()
                                            drops_dict[ip_range][ip][section] = old_dict[ip_range][ip][
                                                section]
                    for ip in compare_dict[ip_range]:
                        if "." not in ip:
                            continue
                        if str(ip) not in old_dict[ip_range]:
                            # ip doesn't exist so add the whole thing
                            adds_dict[ip_range] = dict()
                            adds_dict[ip_range][ip] = compare_dict[ip_range][ip]
                        else:
                            for section in compare_dict[ip_range][ip]:
                                if "stats" in section or "runtime" in section:
                                    continue
                                if not compare_dict[ip_range][ip][section]:
                                    continue
                                if "osmatch" in section:
                                    # special logic due to the dictionaries nested in a list in the osmatch section with the
                                    # first dictionary being the most likely one to match the host
                                    if compare_dict[ip_range][ip]['osmatch'][0]['name'] not in old_dict[ip_range][ip]['osmatch'][0]['name']:
                                        if str(ip) not in adds_dict:
                                            adds_dict[ip_range] = dict()
                                            adds_dict[ip_range][ip] = dict()
                                        adds_dict[ip_range][ip][section] = compare_dict[ip_range][ip][section][0]
                                else:
                                    if compare_dict[ip_range][ip][section] not in old_dict[ip_range][ip][section]:
                                        if str(compare_dict[ip_range][ip][section]).strip():
                                            if ip not in adds_dict:
                                                adds_dict[ip_range] = dict()
                                                adds_dict[ip_range][ip] = dict()
                                            adds_dict[ip_range][ip][section] = compare_dict[ip_range][ip][
                                                section]
                                    elif str(compare_dict[ip_range][ip][section]) not in str(
                                            old_dict[ip_range][ip][section]):
                                        if "dict" in str(type(compare_dict[ip_range][ip][section])):
                                            for key, val in compare_dict[ip_range][ip][section].items():
                                                if str(val) not in str(
                                                        old_dict[ip_range][ip][section].values()):
                                                    if str(val).strip():
                                                        if str(ip) not in adds_dict:
                                                            adds_dict[ip_range] = dict()
                                                            adds_dict[ip_range][ip] = dict()
                                                        adds_dict[ip_range][ip][section] = dict()
                                                        adds_dict[ip_range][ip][section][key] = val
                                        elif "list" in str(type(compare_dict[ip_range][ip][section])):
                                            for subsection in compare_dict[ip_range][ip][section]:
                                                if str(compare_dict[ip_range][ip][section][
                                                           subsection]) not in str(
                                                        old_dict[ip_range][ip][section]):
                                                    if str(compare_dict[ip_range][ip][section][
                                                               subsection]).strip():
                                                        if str(ip) not in adds_dict:
                                                            adds_dict[ip_range] = dict()
                                                            adds_dict[ip_range][ip] = dict()
                                                        adds_dict[ip_range][ip][section] = \
                                                        compare_dict[ip_range][ip][section][subsection]
                                        else:
                                            if str(ip) not in adds_dict:
                                                adds_dict[ip_range] = dict()
                                                adds_dict[ip_range][ip] = dict()
                                            adds_dict[ip_range][ip][section] = compare_dict[ip_range][ip][
                                                section]

            except Exception as err:
                print(f"[**] Scanner: error parsing files {err}, returning full {scan_type} scan data as a string.")
                return str(self.scan_results_dict[scan_type])
            change_flag = True
            if adds_dict:
                adds_dict = str(adds_dict)
            else:
                adds_dict = "None"
            if drops_dict:
                drops_dict = str(drops_dict)
            else:
                drops_dict = "None"
            if adds_dict == "None" and drops_dict == "None":
                change_flag = False
            final_string = f"[**] Scanner: Local_Network_Changes={change_flag}; adds={adds_dict}; drops={drops_dict}."
            print(
                f"[**] Scanner: returning differences between {scan_type} scans as a string."
            )
            print(final_string)
            return final_string

    def pick_scan(
        self,
        scan_type: str = "os",
        scan_report: str = "custom",
        subnet_int: int = 27,
        randomize_bool: bool = False,
        full_report_flag: bool = False,
    ):
        """
        provides options for picking a scan and reporting format
        """
        self.install_nmap()
        scan_type = scan_type.lower()
        scan_report = scan_report.lower()
        if scan_report not in self.report_types_list:
            print(f"[**] Scanner: INVALID {scan_report} report type requested.")
            raise TypeError
        ips = self.check_list(subnet=subnet_int, randomize_scan=randomize_bool)
        print(
            f"[**] Scanner: {scan_type.upper()} scan requested, this can take a while depending on the size of the "
            f"subnet requested, in this case (/{subnet_int})...."
        )
        self.scan_options_dict[scan_type](ips)
        print(
            f"[**] Scanner: {scan_type.upper()} scan completed, beginning {scan_report} report processing."
        )
        if scan_report == "xml":
            self.convert_json_to_xml(self.current_scan_filename)
            return self.xml_reports(self.current_scan_filename, full_report_flag)
        elif scan_report == "json":
            return self.json_reports(self.current_scan_filename, full_report_flag)
        elif scan_report == "custom":
            return self.custom_report(
                self.os_scan_filename_index, scan_type, full_report_flag
            )


class Firewall(State):
    def __init__(self):
        super().__init__()
        """ 
        Enumerate the firewall rules and running mode and forward to Splunk 
        """
        self.state_cmd = "firewall-cmd --state"
        self.rules_cmd = "firewall-cmd --list-all"
        self.old_rules_exist = False
        self.rule_list = list()

    def install_firewalld(self):
        """
        check if installed, if not then attempt a yum install
        """
        firewalld_installed = subprocess.call(["rpm -q firewalld"], shell=True)
        if firewalld_installed != 0:
            try:
                subprocess.call(["yum install -y firewalld"], shell=True)
            except Exception as error:
                print(f"[**] Firewall: yum install of firewalld failed, {error}")

    def firewall(self, full_firewall_data=False):
        """
        break data into state and rules, record current info and send appropriate data to syslog
        """
        # ensure that firewalld is installed first
        self.install_firewalld()
        # if previous-run file exists, copy to .old
        if os.path.exists(f"{self.data_path}/firewall-state.ini"):
            print("[**] Firewall: found previous firewalld configuration report.")
            shutil.copy(
                f"{self.data_path}/firewall-state.ini",
                f"{self.data_path}/firewall-state.ini.old",
            )
            self.old_rules_exist = True
        print("[**] Firewall: generating firewalld configuration report...")
        state = subprocess.Popen(
            [self.state_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
        ).communicate()[0]
        rules = subprocess.Popen(
            [self.rules_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
        ).communicate()[0]

        # clean state
        state = state.strip()
        state = f"firewalld_state='{state}'"

        # clean rules
        rules = rules.splitlines()
        for item in rules:
            item = item.strip()
            item = item.replace("\t", "")
            item = item.replace("=", "='")
            item = item.replace('"', "")
            item = item.replace(": ", "='") + "'"
            item = item.replace(":'", "='NA'")
            item = item.replace(" (active)'", "='active'")
            item = item.replace("source address", "source_address")
            item = item.replace("port port", "port")
            item = item.replace("rule family", "rule_family")
            if "rule_family=" in item:
                item = item.replace(" ", "',")
            item = item.replace("rich rules", "rich_rules")
            item = item.replace(" ", ",")
            self.rule_list.append(item)
        rulestring = "\n".join(self.rule_list)
        rulestring = f"firewalld_rules: {rulestring}"
        print("[**] Firewall: completed firewalld configuration report.")

        # write state and firewalld configuration to file
        with open(os.open(f"{self.data_path}/firewall-state.ini", os.O_CREAT | os.O_WRONLY, 0o600), "w+") as file:
            file.write(state + "\n")
            file.write(rulestring)

        # diff if previous firewalld output exists
        if self.old_rules_exist and not full_firewall_data:
            # diff the two files
            print(f"[**] Firewall: checking diff from previous firewalld state...")
            difference = []
            newlist = []
            oldlist = []
            with open(f"{self.data_path}/firewall-state.ini", "r") as newfirewalld:
                for newline in newfirewalld.readlines():
                    newline = newline.strip()
                    newlist.append(newline)
                with open(
                    f"{self.data_path}/firewall-state.ini.old", "r"
                ) as oldfirewalld:
                    for oldline in oldfirewalld.readlines():
                        oldline = oldline.strip()
                        oldlist.append(oldline)
                    firediff = difflib.unified_diff(
                        newlist,
                        oldlist,
                        fromfile="newfirewalld",
                        tofile="oldfirewalld",
                        n=0,
                    )
                    for eachline in firediff:
                        if not eachline.strip():
                            continue
                        elif eachline.startswith("---"):
                            continue
                        elif eachline.startswith("+++"):
                            continue
                        elif eachline.startswith("@@"):
                            continue
                        if "Checking profiles" in eachline:
                            continue
                        difference.append(eachline.strip())
            if not difference:
                difference = "firewalld_changes='no_change'"
                print("[**] Firewall: no changes to firewalld configuration")
            else:
                diffstring = ", ".join(difference)
                difference = "firewalld_changes=" + diffstring
        else:
            # send all firewalld info to Splunk
            print(f"[**] Firewall: returning all rules")
            difference = rulestring
        return state, difference


class ImplementLynis(State):
    """
    Enumerate security-significant host configurations and forward to Splunk
    """

    def __init__(self):
        super().__init__()
        """ 
        check for lynis installation and yum install if not installed
        this is an architecture choice not to require this package in the rpm spec file
        because this option probably won't be used as much as the openscap option and is provided
        for information / preference / an alternative if not required to use DISA STIGs
        """
        self.run_lynis_cmd = "lynis audit system --verbose"
        # another option could be: `lynis audit system --pentest --verbose`
        # output is stored by default in `/var/log/lynis-report.dat`

    def install_lynis(self):
        """
        check if lynis is installed, if not attempt a yum installation
        """
        lynis_installed = subprocess.call(["rpm -q lynis"], shell=True)
        if lynis_installed != 0:
            try:
                subprocess.call(["yum install -y lynis"], shell=True)
            except Exception as error:
                print(f"[**] ImplementLynis: yum install of lynis failed, {error}")

    def run_lynis(self, full_lynis_flag=False):
        """run lynis and format the output to syslog for ease of review"""
        self.install_lynis()
        if os.path.exists(f"{self.data_path}/lynis.ini"):
            print("[**] ImplementLynis: found previous lynis report.")
            shutil.copy(
                f"{self.data_path}/lynis.ini", f"{self.data_path}/lynis.ini.old"
            )
            print(
                f"[**] ImplementLynis: copied previous lynis report to {self.data_path}/lynis.ini.old."
            )

        # Alternatively if desired could run "lynis -Q"
        print(
            "[**] ImplementLynis: running lynis system audit... this will take a while..."
        )
        state = subprocess.Popen(
            [self.run_lynis_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
        ).communicate()[0]
        print("[**] ImplementLynis: completed running lynis system audit.")
        if state == "":
            print(
                f"[**] ImplementLynis: error running lynis system audit, try running as superuser"
            )

        # write the lynis output to file
        with open(os.open(f"{self.data_path}/lynis.ini", os.O_CREAT | os.O_WRONLY, 0o600), "w+") as new_lynisfile:
            new_lynisfile.write(state)

        # Diff files if old exists
        if os.path.exists(f"{self.data_path}/lynis.ini.old") and not full_lynis_flag:
            print(
                f"[**] ImplementLynis: generating and sending diff from previous lynis system audit to Splunk..."
            )
            # diff the two files
            difference = []
            newlines = []
            oldlines = []
            with open(f"{self.data_path}/lynis.ini", "r") as newlynis:
                # need to remove the date and timestamps so that the diff only catches the system changes,
                # not the date/time changes
                for line in newlynis.readlines():
                    line = line.strip()
                    newlines.append(line)
                with open(f"{self.data_path}/lynis.ini.old", "r") as oldlynis:
                    for old_line in oldlynis.readlines():
                        old_line = old_line.strip()
                        oldlines.append(old_line)
                    diff = difflib.unified_diff(
                        newlines,
                        oldlines,
                        fromfile="newlynis",
                        tofile="oldlynis",
                    )
                    for diff_line in diff:
                        # need to deal with difflib verbosity to remove irrelevant location change info
                        if not diff_line.strip():
                            continue
                        if diff_line.startswith("---"):
                            continue
                        if diff_line.startswith("+++"):
                            continue
                        if diff_line.startswith("@@"):
                            continue
                        if "Checking profiles" in diff_line:
                            continue
                        difference.append(diff_line.strip())
                        print("[**] ImplementLynis: found lynis change " + diff_line)
            if not difference:
                difference = "[**] ImplementLynis: no changes to lynis configuration"
            else:
                difference = ", ".join(difference)
                print(
                    f"[**] ImplementLynis: sending diff from previous lynis system audit to Splunk."
                )
        else:
            """
            the below code probably needs the removal of ansi characters to be a more effective option for parsing
            """
            difference = list()
            print(
                f"[**] ImplementLynis: sending important excerpts from the lynis system audit to Splunk..."
            )
            with open(f"{self.data_path}/lynis.ini", "r") as lynis_file:
                lynis_file = lynis_file.readlines()
                find_regex = re.compile(
                    "(WARNING|PARTIALLY HARDENED|WEAK|DISABLED|SUGGESTION|INACTIVE)"
                )
                for line in lynis_file:
                    line = str(line).strip()
                    if line and len(find_regex.findall(line)) > 0:
                        difference.append(line)
                    else:
                        continue
            difference = ", ".join(difference)
            difference = (
                "[**] ImplementLynis: important lynis host configuration information: "
                + difference
            )
            print(
                f"[**] ImplementLynis: completed sending important excerpts from the lynis system audit to Splunk."
            )
        return difference


# Define the main method
def main():
    # use for testing options and tailoring in python
    #fw = Firewall()
    #fw.firewall(full_firewall_data=True)
    #lynis = ImplementLynis()
    #lynis.run_lynis(full_lynis_flag=True)
    scan = Scanner()
    scan.pick_scan(scan_type="os", scan_report="custom", full_report_flag=True)


# Call the main function
if __name__ == "__main__":
    main()
