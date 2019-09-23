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

import json
import os
import tempfile
import uuid

# import stdlib
from builtins import super

# import third party lib
from requests.exceptions import ConnectionError
from netmiko import file_transfer
from nxapi_plumbing import Device as NXOSDevice
from nxapi_plumbing import NXAPIAuthError, NXAPIConnectionError

# import Incendio Base
from incendio.base import NetworkDriver
from incendio.base.exceptions import CommandErrorException
from incendio.base.exceptions import ConnectionException
from incendio.base.exceptions import MergeConfigException
from incendio.base.exceptions import ReplaceConfigException
from incendio.base.netmiko_helpers import netmiko_args

NETMIKO_MAP = {
    "ios": "cisco_ios",
    "nxos": "cisco_nxos",
    "nxos_ssh": "cisco_nxos",
    "iosxr": "cisco_iosxr",
    "eos": "arista_eos",
    "junos": "juniper_eos",
}


def ensure_netmiko_conn(func):
    """Decorator that ensures Netmiko connection exists."""

    def wrap_function(self, filename=None, config=None):
        try:
            netmiko_object = self._netmiko_device
            if netmiko_object is None:
                raise AttributeError()
        except AttributeError:
            device_type = NETMIKO_MAP[self.platform]
            netmiko_optional_args = self.netmiko_optional_args
            if "port" in netmiko_optional_args:
                netmiko_optional_args["port"] = 22
            self._netmiko_open(
                device_type=device_type, netmiko_optional_args=netmiko_optional_args
            )
        func(self, filename=filename, config=config)

    return wrap_function


class NXOSDriverBase(NetworkDriver):
    """Common code shared between nx-api and nxos_ssh."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.replace = True
        self.loaded = False
        self.changed = False
        self.merge_candidate = ""
        self.candidate_cfg = "candidate_config.txt"
        self.rollback_cfg = "rollback_config.txt"
        self._dest_file_system = optional_args.pop("dest_file_system", "bootflash:")
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.device = None

    @ensure_netmiko_conn
    def load_replace_candidate(self, filename=None, config=None):

        if not filename and not config:
            raise ReplaceConfigException(
                "filename or config parameter must be provided."
            )

        if not filename:
            tmp_file = self._create_tmp_file(config)
            filename = tmp_file
        else:
            if not os.path.isfile(filename):
                raise ReplaceConfigException("File {} not found".format(filename))

        try:
            transfer_result = file_transfer(
                self._netmiko_device,
                source_file=filename,
                dest_file=self.candidate_cfg,
                file_system=self._dest_file_system,
                direction="put",
                overwrite_file=True,
            )
            if not transfer_result["file_exists"]:
                raise ValueError()
        except Exception:
            msg = (
                "Could not transfer file. There was an error "
                "during transfer. Please make sure remote "
                "permissions are set."
            )
            raise ReplaceConfigException(msg)

        self.replace = True
        self.loaded = True
        if config and os.path.isfile(tmp_file):
            os.remove(tmp_file)

    def load_merge_candidate(self, filename=None, config=None):
        if not filename and not config:
            raise MergeConfigException("filename or config param must be provided.")

        self.merge_candidate += "\n"  # insert one extra line
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate += f.read()
        else:
            self.merge_candidate += config
        self.replace = False
        self.loaded = True

    def _send_command(self, command, raw_text=False):
        raise NotImplementedError

    def _commit_merge(self):
        try:
            output = self._send_config(self.merge_candidate)
            if output and "Invalid command" in output:
                raise MergeConfigException("Error while applying config!")
        except Exception as e:
            self.changed = True
            self.rollback()
            raise MergeConfigException(str(e))

        self.changed = True
        # clear the merge buffer
        self.merge_candidate = ""

    def _get_merge_diff(self):
        """
        The merge diff is not necessarily what needs to be loaded
        for example under NTP, even though the 'ntp commit' command might be
        alread configured, it is mandatory to be sent
        otherwise it won't take the new configuration - see:
        https://github.com/napalm-automation/napalm-nxos/issues/59
        therefore this method will return the real diff (but not necessarily what is
        being sent by the merge_load_config()
        """
        diff = []
        running_config = self.get_config(retrieve="running")["running"]
        running_lines = running_config.splitlines()
        for line in self.merge_candidate.splitlines():
            if line not in running_lines and line:
                if line[0].strip() != "!":
                    diff.append(line)
        return "\n".join(diff)

    def _get_diff(self):
        """Get a diff between running config and a proposed file."""
        diff = []
        self._create_sot_file()
        diff_out = self._send_command(
            "show diff rollback-patch file {} file {}".format(
                "sot_file", self.candidate_cfg
            ),
            raw_text=True,
        )
        try:
            diff_out = (
                diff_out.split("Generating Rollback Patch")[1]
                .replace("Rollback Patch is Empty", "")
                .strip()
            )
            for line in diff_out.splitlines():
                if line:
                    if line[0].strip() != "!" and line[0].strip() != ".":
                        diff.append(line.rstrip(" "))
        except (AttributeError, KeyError):
            raise ReplaceConfigException(
                "Could not calculate diff. It's possible the given file doesn't exist."
            )
        return "\n".join(diff)

    def compare_config(self):
        if self.loaded:
            if not self.replace:
                return self._get_merge_diff()
            diff = self._get_diff()
            return diff
        return ""

    def commit_config(self, message=""):
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        if self.loaded:
            # Create checkpoint from current running-config
            self._save_to_checkpoint(self.rollback_cfg)

            if self.replace:
                self._load_cfg_from_checkpoint()
            else:
                self._commit_merge()

            try:
                # If hostname changes ensure Netmiko state is updated properly
                self._netmiko_device.set_base_prompt()
            except AttributeError:
                pass

            self._copy_run_start()
            self.loaded = False
        else:
            raise ReplaceConfigException("No config loaded.")

    def discard_config(self):
        if self.loaded:
            # clear the buffer
            self.merge_candidate = ""
        if self.loaded and self.replace:
            self._delete_file(self.candidate_cfg)
        self.loaded = False

    def _create_sot_file(self):
        """Create Source of Truth file to compare."""

        # Bug on on NX-OS 6.2.16 where overwriting sot_file would take exceptionally long time
        # (over 12 minutes); so just delete the sot_file
        try:
            self._delete_file(filename="sot_file")
        except Exception:
            pass
        commands = [
            "terminal dont-ask",
            "checkpoint file sot_file",
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def _get_checkpoint_file(self):
        filename = "temp_cp_file_from_incendio"
        self._set_checkpoint(filename)
        command = "show file {}".format(filename)
        output = self._send_command(command, raw_text=True)
        self._delete_file(filename)
        return output

    def _set_checkpoint(self, filename):
        commands = [
            "terminal dont-ask",
            "checkpoint file {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def _save_to_checkpoint(self, filename):
        """Save the current running config to the given file."""
        commands = [
            "terminal dont-ask",
            "checkpoint file {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def _delete_file(self, filename):
        commands = [
            "terminal dont-ask",
            "delete {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    @staticmethod
    def _create_tmp_file(config):
        tmp_dir = tempfile.gettempdir()
        rand_fname = str(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, "wt") as fobj:
            fobj.write(config)
        return filename

    def _disable_confirmation(self):
        self._send_command_list(["terminal dont-ask"])

    def get_config(self, retrieve="all", full=False):
        config = {"startup": "", "running": "", "candidate": ""}  # default values
        # NX-OS only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve.lower() in ("running", "all"):
            command = "show running-config{}".format(run_full)
            config["running"] = str(self._send_command(command, raw_text=True))
        if retrieve.lower() in ("startup", "all"):
            command = "show startup-config"
            config["startup"] = str(self._send_command(command, raw_text=True))
        return config

    @staticmethod
    def _get_table_rows(parent_table, table_name, row_name):
        """
        Inconsistent behavior:
        {'TABLE_intf': [{'ROW_intf': {
        vs
        {'TABLE_mac_address': {'ROW_mac_address': [{
        vs
        {'TABLE_vrf': {'ROW_vrf': {'TABLE_adj': {'ROW_adj': {
        """
        if parent_table is None:
            return []
        _table = parent_table.get(table_name)
        _table_rows = []
        if isinstance(_table, list):
            _table_rows = [_table_row.get(row_name) for _table_row in _table]
        elif isinstance(_table, dict):
            _table_rows = _table.get(row_name)
        if not isinstance(_table_rows, list):
            _table_rows = [_table_rows]
        return _table_rows

    def _get_reply_table(self, result, table_name, row_name):
        return self._get_table_rows(result, table_name, row_name)

    def _get_command_table(self, command, table_name, row_name):
        json_output = self._send_command(command)
        if type(json_output) is not dict:
            json_output = json.loads(json_output)
        return self._get_reply_table(json_output, table_name, row_name)


class NXOSDriver(NXOSDriverBase):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(
            hostname, username, password, timeout=timeout, optional_args=optional_args
        )
        if optional_args is None:
            optional_args = {}

        # nxos_protocol is there for backwards compatibility, transport is the preferred method
        self.transport = optional_args.get(
            "transport", optional_args.get("nxos_protocol", "https")
        )
        if self.transport == "https":
            self.port = optional_args.get("port", 443)
        elif self.transport == "http":
            self.port = optional_args.get("port", 80)

        self.ssl_verify = optional_args.get("ssl_verify", False)
        self.platform = "nxos"

    def open(self):
        try:
            self.device = NXOSDevice(
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=self.port,
                transport=self.transport,
                verify=self.ssl_verify,
                api_format="jsonrpc",
            )
            self._send_command("show hostname")
        except (NXAPIConnectionError, NXAPIAuthError):
            # unable to open connection
            raise ConnectionException("Cannot connect to {}".format(self.hostname))

    def close(self):
        self.device = None

    def _send_command(self, command, raw_text=False):
        """
        Wrapper for NX-API show method.

        Allows more code sharing between NX-API and SSH.
        """
        return self.device.show(command, raw_text=raw_text)

    def _send_command_list(self, commands):
        return self.device.config_list(commands)

    def _send_config(self, commands):
        if isinstance(commands, str):
            # Has to be a list generator and not generator expression (not JSON serializable)
            commands = [command for command in commands.splitlines() if command]
        return self.device.config_list(commands)

    def _copy_run_start(self):
        results = self.device.save(filename="startup-config")
        if not results:
            msg = "Unable to save running-config to startup-config!"
            raise CommandErrorException(msg)

    def _load_cfg_from_checkpoint(self):
        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.candidate_cfg),
            "no terminal dont-ask",
        ]
        try:
            rollback_result = self._send_command_list(commands)
        except ConnectionError:
            # requests will raise an error with verbose warning output (don't fail on this).
            return
        finally:
            self.changed = True

        # For nx-api a list is returned so extract the result associated with the
        # 'rollback' command.
        rollback_result = rollback_result[1]
        msg = (
            rollback_result.get("msg")
            if rollback_result.get("msg")
            else rollback_result
        )
        error_msg = True if rollback_result.get("error") else False

        if "Rollback failed." in msg or error_msg:
            raise ReplaceConfigException(msg)
        elif rollback_result == []:
            raise ReplaceConfigException

    def rollback(self):
        if self.changed:
            self.device.rollback(self.rollback_cfg)
            self._copy_run_start()
            self.changed = False

    def cli(self, commands):
        cli_output = {}
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            command_output = self._send_command(command, raw_text=True)
            cli_output[str(command)] = command_output
        return cli_output
