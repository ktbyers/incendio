# -*- coding: utf-8 -*-
# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

# import Incendio base
from incendio.base.netmiko_helpers import netmiko_args
from incendio.base.base import NetworkDriver
from incendio.base.exceptions import ConnectionException
from incendio.base.exceptions import MergeConfigException
from incendio.base.exceptions import ReplaceConfigException
from incendio.base.exceptions import CommandTimeoutException

# import incendio pyIOSXR
from incendio.pyIOSXR import IOSXR
from incendio.pyIOSXR.exceptions import ConnectError
from incendio.pyIOSXR.exceptions import TimeoutError
from incendio.pyIOSXR.exceptions import InvalidInputError


class IOSXRDriver(NetworkDriver):
    """IOS-XR driver class: inherits NetworkDriver from incendio.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        if optional_args is None:
            optional_args = {}
        self.lock_on_connect = optional_args.get("config_lock", False)

        self.netmiko_optional_args = netmiko_args(optional_args)
        try:
            self.port = self.netmiko_optional_args.pop("port")
        except KeyError:
            self.port = 22

        self.platform = "iosxr"
        self.device = IOSXR(
            hostname,
            username,
            password,
            timeout=timeout,
            port=self.port,
            lock=self.lock_on_connect,
            **self.netmiko_optional_args
        )

    def open(self):
        try:
            self.device.open()
        except ConnectError as conn_err:
            raise ConnectionException(conn_err.args[0])

    def close(self):
        self.device.close()

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        # Simply returns the flag from pyIOSXR
        return {"is_alive": self.device.is_alive()}

    def load_replace_candidate(self, filename=None, config=None):
        self.pending_changes = True
        self.replace = True
        if not self.lock_on_connect:
            self.device.lock()

        try:
            self.device.load_candidate_config(filename=filename, config=config)
        except InvalidInputError as e:
            self.pending_changes = False
            self.replace = False
            raise ReplaceConfigException(e.args[0])

    def load_merge_candidate(self, filename=None, config=None):
        self.pending_changes = True
        self.replace = False
        if not self.lock_on_connect:
            self.device.lock()

        try:
            self.device.load_candidate_config(filename=filename, config=config)
        except InvalidInputError as e:
            self.pending_changes = False
            self.replace = False
            raise MergeConfigException(e.args[0])

    def compare_config(self):
        if not self.pending_changes:
            return ""
        elif self.replace:
            return self.device.compare_replace_config().strip()
        else:
            return self.device.compare_config().strip()

    def commit_config(self, message=""):
        commit_args = {"comment": message} if message else {}
        if self.replace:
            self.device.commit_replace_config(**commit_args)
        else:
            self.device.commit_config(**commit_args)
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def discard_config(self):
        self.device.discard_config()
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def rollback(self):
        self.device.rollback()

    def cli(self, commands):

        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                cli_output[str(command)] = str(self.device._execute_show(command))
            except TimeoutError:
                cli_output[
                    str(command)
                ] = 'Execution of command \
                    "{command}" took too long! Please adjust your params!'.format(
                    command=command
                )
                raise CommandTimeoutException(str(cli_output))

        return cli_output
