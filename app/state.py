"""
    state.py
    helper class to store program and host information
"""
import queue
import sys
import os
import platform
import datetime
import logging
import logging.config
import logging.handlers


class State:
    """Holds current state of the program"""

    def __init__(self):
        self.app_name = "rhelhostinfo"
        self.maj_version = 1
        self.min_version = 0
        self.title = f"{self.app_name} v{self.maj_version}.{self.min_version}"
        self.queue = queue.Queue()
        self.default_path = "/opt"
        self.app_path = f"/opt/{self.app_name}"
        self.log_path = f"{self.app_path}/log"
        self.debug_path = f"{self.app_path}/debug"
        self.data_path = f"{self.app_path}/data"
        self.dir_list = [self.log_path, self.data_path, self.debug_path]
        self.hostname = platform.node()
        self.message_count = 0
        self.start_time = datetime.datetime.today()
        if getattr(sys, "frozen", False):
            # If the application is run as a bundle, the PyInstaller bootloader
            # extends the sys module by a flag frozen=True and sets the app
            # path into variable _MEIPASS'.
            self.application_path = os.path.dirname(sys.executable)
        else:
            self.application_path = os.path.dirname(os.path.abspath(__file__))
        self.log_conf_path = f"{self.application_path}/log.conf"
        self.syslog_path = f"{self.application_path}/syslog.conf"

        # test to make sure the app will work on this os
        if sys.platform.lower() != "linux":
            print(
                f"[**] **WARNING** The operating system {sys.platform} has not been tested for compatibility with {self.title}."
            )
            print(
                f"[**] **WARNING** Please test for compatibility and edit the codebase before proceeding."
            )
            sys.exit(1)

    def mkdirs(self):
        """Double check that the directories created on install still exist and if not, then create them"""
        dir_access = os.access(f"{self.app_path}", os.R_OK | os.W_OK)
        if not dir_access:
            print(
                f"[**] **WARNING** The directory {self.app_path} does not have permissions that allow {self.app_name} to read and write. Please correct this and try {self.app_name} again."
            )
            sys.exit(1)
        else:
            for directory in self.dir_list:
                if not os.path.exists(directory):
                    print(
                    f"[**] {self.app_name} cannot access {directory}, trying to make the directory."
                    )
                    os.makedirs(directory)

    def remote_notify(self, level=2, message=""):
        """
        Logs messages to syslog at the specified severity level
        """
        self.message_count += 1
        logging.config.fileConfig(f"{self.syslog_path}", disable_existing_loggers=False)
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
