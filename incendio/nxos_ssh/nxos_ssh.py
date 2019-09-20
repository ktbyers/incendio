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

from __future__ import unicode_literals

import socket

# import stdlib
from builtins import super

# import NAPALM Base
from incendio.base.exceptions import CommandErrorException, ReplaceConfigException
from incendio.base.utils import py23_compat
from incendio.nxos import NXOSDriverBase


class NXOSSSHDriver(NXOSDriverBase):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(
            hostname, username, password, timeout=timeout, optional_args=optional_args
        )
        self.platform = "nxos_ssh"

    def open(self):
        self.device = self._netmiko_open(
            device_type="cisco_nxos", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        self._netmiko_close()

    def _send_command(self, command, raw_text=False):
        """
        Wrapper for Netmiko's send_command method.

        raw_text argument is not used and is for code sharing with NX-API.
        """
        return self.device.send_command(command)

    def _send_command_list(self, commands, expect_string=None):
        """Wrapper for Netmiko's send_command method (for list of commands."""
        output = ""
        for command in commands:
            output += self.device.send_command(
                command,
                strip_prompt=False,
                strip_command=False,
                expect_string=expect_string,
            )
        return output

    def _send_config(self, commands):
        if isinstance(commands, py23_compat.string_types):
            commands = (command for command in commands.splitlines() if command)
        return self.device.send_config_set(commands)

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            if self.device is None:
                return {"is_alive": False}
            else:
                # Try sending ASCII null byte to maintain the connection alive
                self._send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable,
            # hence return False.
            return {"is_alive": False}
        return {"is_alive": self.device.remote_conn.transport.is_active()}

    def _copy_run_start(self):

        output = self.device.save_config()
        if "complete" in output.lower():
            return True
        else:
            msg = "Unable to save running-config to startup-config!"
            raise CommandErrorException(msg)

    def _load_cfg_from_checkpoint(self):

        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.candidate_cfg),
            "no terminal dont-ask",
        ]

        try:
            rollback_result = self._send_command_list(commands, expect_string=r"[#>]")
        finally:
            self.changed = True
        msg = rollback_result
        if "Rollback failed." in msg:
            raise ReplaceConfigException(msg)

    def rollback(self):
        if self.changed:
            commands = [
                "terminal dont-ask",
                "rollback running-config file {}".format(self.rollback_cfg),
                "no terminal dont-ask",
            ]
            result = self._send_command_list(commands, expect_string=r"[#>]")
            if "completed" not in result.lower():
                raise ReplaceConfigException(result)
            # If hostname changes ensure Netmiko state is updated properly
            self._netmiko_device.set_base_prompt()
            self._copy_run_start()
            self.changed = False

    def cli(self, commands):
        cli_output = {}
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            cli_output[py23_compat.text_type(command)] = output
        return cli_output
