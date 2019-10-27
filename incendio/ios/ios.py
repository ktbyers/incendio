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

import functools
import os
import re
import socket
import telnetlib
import tempfile
import uuid

from netmiko import FileTransfer, InLineTransfer

from incendio.base.base import NetworkDriver
from incendio.base.exceptions import (
    ReplaceConfigException,
    MergeConfigException,
    ConnectionClosedException,
    CommandErrorException,
)
from incendio.base.netmiko_helpers import netmiko_args

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = (
    r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:"
    "[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}"
)
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(
    IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3
)

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"
INT_REGEX = r"(^\w{1,2}\d{1,3}/\d{1,2}|^\w{1,2}\d{1,3})"
RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_IPADDR_STRIP = re.compile(r"({})\n".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"

IOS_COMMANDS = {
    "show_mac_address": ["show mac-address-table", "show mac address-table"]
}

AFI_COMMAND_MAP = {
    "IPv4 Unicast": "ipv4 unicast",
    "IPv6 Unicast": "ipv6 unicast",
    "VPNv4 Unicast": "vpnv4 all",
    "VPNv6 Unicast": "vpnv6 unicast all",
    "IPv4 Multicast": "ipv4 multicast",
    "IPv6 Multicast": "ipv6 multicast",
    "L2VPN E-VPN": "l2vpn evpn",
    "MVPNv4 Unicast": "ipv4 mvpn all",
    "MVPNv6 Unicast": "ipv6 mvpn all",
    "VPNv4 Flowspec": "ipv4 flowspec",
    "VPNv6 Flowspec": "ipv6 flowspec",
}


class IOSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self._napalm_conn = optional_args.get("_napalm_conn")
        self.transport = optional_args.get("transport", "ssh")

        # Retrieve file names
        self.candidate_cfg = optional_args.get("candidate_cfg", "candidate_config.txt")
        self.merge_cfg = optional_args.get("merge_cfg", "merge_config.txt")
        self.rollback_cfg = optional_args.get("rollback_cfg", "rollback_config.txt")
        self.inline_transfer = optional_args.get("inline_transfer", False)
        if self.transport == "telnet":
            # Telnet only supports inline_transfer
            self.inline_transfer = True

        # None will cause autodetection of dest_file_system
        self._dest_file_system = optional_args.get("dest_file_system", None)
        self.auto_rollback_on_error = optional_args.get("auto_rollback_on_error", True)

        # Control automatic execution of 'file prompt quiet' for file operations
        self.auto_file_prompt = optional_args.get("auto_file_prompt", True)

        # Track whether 'file prompt quiet' has been changed.
        self.prompt_quiet_changed = False
        # Track whether 'file prompt quiet' is known to be configured
        self.prompt_quiet_configured = None

        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        self.device = None
        self.config_replace = False

        self.platform = "ios"
        self.profile = [self.platform]
        self.use_canonical_interface = optional_args.get("canonical_int", False)

    def open(self):
        """Open a connection to the device."""
        if self._napalm_conn:
            self.device = self._napalm_conn
        else:
            device_type = "cisco_ios"
            if self.transport == "telnet":
                device_type = "cisco_ios_telnet"
            self.device = self._netmiko_open(
                device_type, netmiko_optional_args=self.netmiko_optional_args
            )

    def _discover_file_system(self):
        try:
            return self.device._autodetect_fs()
        except Exception:
            msg = (
                "Netmiko _autodetect_fs failed (to workaround specify "
                "dest_file_system in optional_args.)"
            )
            raise CommandErrorException(msg)

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""

        # Return file prompt quiet to the original state
        if self.auto_file_prompt and self.prompt_quiet_changed is True:
            self.device.send_config_set(["no file prompt quiet"])
            self.prompt_quiet_changed = False
            self.prompt_quiet_configured = False
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        if self.transport == "telnet":
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {"is_alive": True}
            except UnicodeDecodeError:
                # Netmiko logging bug (remove after Netmiko >= 1.4.3)
                return {"is_alive": True}
            except AttributeError:
                return {"is_alive": False}
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {"is_alive": self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {"is_alive": False}
        return {"is_alive": False}

    @staticmethod
    def _create_tmp_file(config):
        """Write temp file and for use with inline config and SCP."""
        tmp_dir = tempfile.gettempdir()
        rand_fname = str(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, "wt") as fobj:
            fobj.write(config)
        return filename

    def _load_candidate_wrapper(
        self, source_file=None, source_config=None, dest_file=None, file_system=None
    ):
        """
        Transfer file to remote device for either merge or replace operations

        Returns (return_status, msg)
        """
        return_status = False
        msg = ""
        if source_file and source_config:
            raise ValueError("Cannot simultaneously set source_file and source_config")

        if source_config:
            if self.inline_transfer:
                (return_status, msg) = self._inline_tcl_xfer(
                    source_config=source_config,
                    dest_file=dest_file,
                    file_system=file_system,
                )
            else:
                # Use SCP
                tmp_file = self._create_tmp_file(source_config)
                (return_status, msg) = self._scp_file(
                    source_file=tmp_file, dest_file=dest_file, file_system=file_system
                )
                if tmp_file and os.path.isfile(tmp_file):
                    os.remove(tmp_file)
        if source_file:
            if self.inline_transfer:
                (return_status, msg) = self._inline_tcl_xfer(
                    source_file=source_file,
                    dest_file=dest_file,
                    file_system=file_system,
                )
            else:
                (return_status, msg) = self._scp_file(
                    source_file=source_file,
                    dest_file=dest_file,
                    file_system=file_system,
                )
        if not return_status:
            if msg == "":
                msg = "Transfer to remote device failed"
        return (return_status, msg)

    def load_replace_candidate(self, filename=None, config=None):
        """
        SCP file to device filesystem, defaults to candidate_config.

        Return None or raise exception
        """
        self.config_replace = True
        return_status, msg = self._load_candidate_wrapper(
            source_file=filename,
            source_config=config,
            dest_file=self.candidate_cfg,
            file_system=self.dest_file_system,
        )
        if not return_status:
            raise ReplaceConfigException(msg)

    def load_merge_candidate(self, filename=None, config=None):
        """
        SCP file to remote device.

        Merge configuration in: copy <file> running-config
        """
        self.config_replace = False
        return_status, msg = self._load_candidate_wrapper(
            source_file=filename,
            source_config=config,
            dest_file=self.merge_cfg,
            file_system=self.dest_file_system,
        )
        if not return_status:
            raise MergeConfigException(msg)

    def _normalize_compare_config(self, diff):
        """Filter out strings that should not show up in the diff."""
        ignore_strings = [
            "Contextual Config Diffs",
            "No changes were found",
            "ntp clock-period",
        ]
        if self.auto_file_prompt:
            ignore_strings.append("file prompt quiet")

        new_list = []
        for line in diff.splitlines():
            for ignore in ignore_strings:
                if ignore in line:
                    break
            else:  # nobreak
                new_list.append(line)
        return "\n".join(new_list)

    @staticmethod
    def _normalize_merge_diff_incr(diff):
        """Make the compare config output look better.

        Cisco IOS incremental-diff output

        No changes:
        !List of Commands:
        end
        !No changes were found
        """
        new_diff = []

        changes_found = False
        for line in diff.splitlines():
            if re.search(r"order-dependent line.*re-ordered", line):
                changes_found = True
            elif "No changes were found" in line:
                # IOS in the re-order case still claims "No changes were found"
                if not changes_found:
                    return ""
                else:
                    continue

            if line.strip() == "end":
                continue
            elif "List of Commands" in line:
                continue
            # Filter blank lines and prepend +sign
            elif line.strip():
                if re.search(r"^no\s+", line.strip()):
                    new_diff.append("-" + line)
                else:
                    new_diff.append("+" + line)
        return "\n".join(new_diff)

    @staticmethod
    def _normalize_merge_diff(diff):
        """Make compare_config() for merge look similar to replace config diff."""
        new_diff = []
        for line in diff.splitlines():
            # Filter blank lines and prepend +sign
            if line.strip():
                new_diff.append("+" + line)
        if new_diff:
            new_diff.insert(
                0, "! incremental-diff failed; falling back to echo of merge file"
            )
        else:
            new_diff.append("! No changes specified in merge file.")
        return "\n".join(new_diff)

    def compare_config(self):
        """
        show archive config differences <base_file> <new_file>.

        Default operation is to compare system:running-config to self.candidate_cfg
        """
        # Set defaults
        base_file = "running-config"
        base_file_system = "system:"
        if self.config_replace:
            new_file = self.candidate_cfg
        else:
            new_file = self.merge_cfg
        new_file_system = self.dest_file_system

        base_file_full = self._gen_full_path(
            filename=base_file, file_system=base_file_system
        )
        new_file_full = self._gen_full_path(
            filename=new_file, file_system=new_file_system
        )

        if self.config_replace:
            cmd = "show archive config differences {} {}".format(
                base_file_full, new_file_full
            )
            diff = self.device.send_command_expect(cmd)
            diff = self._normalize_compare_config(diff)
        else:
            # merge
            cmd = "show archive config incremental-diffs {} ignorecase".format(
                new_file_full
            )
            diff = self.device.send_command_expect(cmd)
            if "error code 5" in diff or "returned error 5" in diff:
                diff = (
                    "You have encountered the obscure 'error 5' message. This generally "
                    "means you need to add an 'end' statement to the end of your merge changes."
                )
            elif "% Invalid" not in diff:
                diff = self._normalize_merge_diff_incr(diff)
            else:
                cmd = "more {}".format(new_file_full)
                diff = self.device.send_command_expect(cmd)
                diff = self._normalize_merge_diff(diff)

        return diff.strip()

    def _file_prompt_quiet(f):
        """Decorator to toggle 'file prompt quiet' for methods that perform file operations."""

        @functools.wraps(f)
        def wrapper(self, *args, **kwargs):
            if not self.prompt_quiet_configured:
                if self.auto_file_prompt:
                    # disable file operation prompts
                    self.device.send_config_set(["file prompt quiet"])
                    self.prompt_quiet_changed = True
                    self.prompt_quiet_configured = True
                else:
                    # check if the command is already in the running-config
                    cmd = "file prompt quiet"
                    show_cmd = "show running-config | inc {}".format(cmd)
                    output = self.device.send_command_expect(show_cmd)
                    if cmd in output:
                        self.prompt_quiet_configured = True
                    else:
                        msg = (
                            "on-device file operations require prompts to be disabled. "
                            "Configure 'file prompt quiet' or set 'auto_file_prompt=True'"
                        )
                        raise CommandErrorException(msg)

            # call wrapped function
            return f(self, *args, **kwargs)

        return wrapper

    @_file_prompt_quiet
    def _commit_handler(self, cmd):
        """
        Special handler for hostname change on commit operation. Also handles username removal
        which prompts for confirmation (username removal prompts for each user...)
        """
        current_prompt = self.device.find_prompt().strip()
        terminating_char = current_prompt[-1]
        # Look for trailing pattern that includes '#' and '>'
        pattern1 = r"[>#{}]\s*$".format(terminating_char)
        # Handle special username removal pattern
        pattern2 = r".*all username.*confirm"
        patterns = r"(?:{}|{})".format(pattern1, pattern2)
        output = self.device.send_command_expect(cmd, expect_string=patterns)
        loop_count = 50
        new_output = output
        for i in range(loop_count):
            if re.search(pattern2, new_output):
                # Send confirmation if username removal
                new_output = self.device.send_command_timing(
                    "\n", strip_prompt=False, strip_command=False
                )
                output += new_output
            else:
                break
        # Reset base prompt in case hostname changed
        self.device.set_base_prompt()
        return output

    def commit_config(self, message=""):
        """
        If replacement operation, perform 'configure replace' for the entire config.

        If merge operation, perform copy <file> running-config.
        """
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        # Always generate a rollback config on commit
        self._gen_rollback_cfg()

        if self.config_replace:
            # Replace operation
            filename = self.candidate_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise ReplaceConfigException("Candidate config file does not exist")
            if self.auto_rollback_on_error:
                cmd = "configure replace {} force revert trigger error".format(cfg_file)
            else:
                cmd = "configure replace {} force".format(cfg_file)
            output = self._commit_handler(cmd)
            if (
                ("original configuration has been successfully restored" in output)
                or ("error" in output.lower())
                or ("not a valid config file" in output.lower())
                or ("failed" in output.lower())
            ):
                msg = "Candidate config could not be applied\n{}".format(output)
                raise ReplaceConfigException(msg)
            elif "%Please turn config archive on" in output:
                msg = "Cisco IOS replace() requires 'archive' feature to be enabled."
                raise ReplaceConfigException(msg)
        else:
            # Merge operation
            filename = self.merge_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise MergeConfigException("Merge source config file does not exist")
            cmd = "copy {} running-config".format(cfg_file)
            output = self._commit_handler(cmd)
            if "Invalid input detected" in output:
                self.rollback()
                err_header = "Configuration merge failed; automatic rollback attempted"
                merge_error = "{0}:\n{1}".format(err_header, output)
                raise MergeConfigException(merge_error)

        # After a commit - we no longer know whether this is configured or not.
        self.prompt_quiet_configured = None

        # Save config to startup (both replace and merge)
        output += self.device.save_config()

    def discard_config(self):
        """Discard loaded candidate configurations."""
        self._discard_config()

    @_file_prompt_quiet
    def _discard_config(self):
        """Set candidate_cfg to current running-config. Erase the merge_cfg file."""
        discard_candidate = "copy running-config {}".format(
            self._gen_full_path(self.candidate_cfg)
        )
        discard_merge = "copy null: {}".format(self._gen_full_path(self.merge_cfg))
        self.device.send_command_expect(discard_candidate)
        self.device.send_command_expect(discard_merge)

    def rollback(self):
        """Rollback configuration to filename or to self.rollback_cfg file."""
        filename = self.rollback_cfg
        cfg_file = self._gen_full_path(filename)
        if not self._check_file_exists(cfg_file):
            raise ReplaceConfigException("Rollback config file does not exist")
        cmd = "configure replace {} force".format(cfg_file)
        self._commit_handler(cmd)

        # After a rollback - we no longer know whether this is configured or not.
        self.prompt_quiet_configured = None

        # Save config to startup
        self.device.save_config()

    def _inline_tcl_xfer(
        self, source_file=None, source_config=None, dest_file=None, file_system=None
    ):
        """
        Use Netmiko InlineFileTransfer (TCL) to transfer file or config to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        if source_file:
            return self._xfer_file(
                source_file=source_file,
                dest_file=dest_file,
                file_system=file_system,
                TransferClass=InLineTransfer,
            )
        if source_config:
            return self._xfer_file(
                source_config=source_config,
                dest_file=dest_file,
                file_system=file_system,
                TransferClass=InLineTransfer,
            )
        raise ValueError("File source not specified for transfer.")

    def _scp_file(self, source_file, dest_file, file_system):
        """
        SCP file to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        return self._xfer_file(
            source_file=source_file,
            dest_file=dest_file,
            file_system=file_system,
            TransferClass=FileTransfer,
        )

    def _xfer_file(
        self,
        source_file=None,
        source_config=None,
        dest_file=None,
        file_system=None,
        TransferClass=FileTransfer,
    ):
        """Transfer file to remote device.

        By default, this will use Secure Copy if self.inline_transfer is set, then will use
        Netmiko InlineTransfer method to transfer inline using either SSH or telnet (plus TCL
        onbox).

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        if not source_file and not source_config:
            raise ValueError("File source not specified for transfer.")
        if not dest_file or not file_system:
            raise ValueError("Destination file or file system not specified.")

        if source_file:
            kwargs = dict(
                ssh_conn=self.device,
                source_file=source_file,
                dest_file=dest_file,
                direction="put",
                file_system=file_system,
            )
        elif source_config:
            kwargs = dict(
                ssh_conn=self.device,
                source_config=source_config,
                dest_file=dest_file,
                direction="put",
                file_system=file_system,
            )
        use_scp = True
        if self.inline_transfer:
            use_scp = False

        with TransferClass(**kwargs) as transfer:

            # Check if file already exists and has correct MD5
            if transfer.check_file_exists() and transfer.compare_md5():
                msg = "File already exists and has correct MD5: no SCP needed"
                return (True, msg)
            if not transfer.verify_space_available():
                msg = "Insufficient space available on remote device"
                return (False, msg)

            if use_scp:
                cmd = "ip scp server enable"
                show_cmd = "show running-config | inc {}".format(cmd)
                output = self.device.send_command_expect(show_cmd)
                if cmd not in output:
                    msg = (
                        "SCP file transfers are not enabled. "
                        "Configure 'ip scp server enable' on the device."
                    )
                    raise CommandErrorException(msg)

            # Transfer file
            transfer.transfer_file()

            # Compares MD5 between local-remote files
            if transfer.verify_file():
                msg = "File successfully transferred to remote device"
                return (True, msg)
            else:
                msg = "File transfer to remote device failed"
                return (False, msg)
            return (False, "")

    def _gen_full_path(self, filename, file_system=None):
        """Generate full file path on remote device."""
        if file_system is None:
            return "{}/{}".format(self.dest_file_system, filename)
        else:
            if ":" not in file_system:
                raise ValueError(
                    "Invalid file_system specified: {}".format(file_system)
                )
            return "{}/{}".format(file_system, filename)

    @_file_prompt_quiet
    def _gen_rollback_cfg(self):
        """Save a configuration that can be used for rollback."""
        cfg_file = self._gen_full_path(self.rollback_cfg)
        cmd = "copy running-config {}".format(cfg_file)
        self.device.send_command_expect(cmd)

    def _check_file_exists(self, cfg_file):
        """
        Check that the file exists on remote device using full path.

        cfg_file is full path i.e. flash:/file_name

        For example
        # dir flash:/candidate_config.txt
        Directory of flash:/candidate_config.txt

        33  -rw-        5592  Dec 18 2015 10:50:22 -08:00  candidate_config.txt

        return boolean
        """
        cmd = "dir {}".format(cfg_file)
        success_pattern = "Directory of {}".format(cfg_file)
        output = self.device.send_command_expect(cmd)
        if "Error opening" in output:
            return False
        elif success_pattern in output:
            return True
        return False

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command().

        Remove "Load for five sec; one minute if in output"
        Remove "Time source is"
        """
        output = re.sub(r"^Load for five secs.*$", "", output, flags=re.M)
        output = re.sub(r"^Time source is .*$", "", output, flags=re.M)
        return output.strip()

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['show clock', 'show calendar']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    @property
    def dest_file_system(self):
        # The self.device check ensures incendio has an open connection
        if self.device and self._dest_file_system is None:
            self._dest_file_system = self._discover_file_system()
        return self._dest_file_system

    def get_config(self, retrieve="all", full=False):
        """Implementation of get_config for IOS.
        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        configs = {"startup": "", "running": "", "candidate": ""}
        # IOS only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve in ("startup", "all"):
            command = "show startup-config"
            output = self._send_command(command)
            configs["startup"] = output

        if retrieve in ("running", "all"):
            command = "show running-config{}".format(run_full)
            output = self._send_command(command)
            configs["running"] = output

        return configs
