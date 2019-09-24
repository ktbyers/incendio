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

# std libs
import re

from datetime import datetime
import inspect

# third party libs
import pyeapi
from pyeapi.eapilib import ConnectionError

# Incendio base
from incendio.base.base import NetworkDriver
from incendio.base.exceptions import (
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
    SessionLockedException,
    CommandErrorException,
)


class EOSDriver(NetworkDriver):
    """Incendio driver for Arista EOS."""

    SUPPORTED_OC_MODELS = []

    HEREDOC_COMMANDS = [
        ("banner login", 1),
        ("banner motd", 1),
        ("comment", 1),
        ("protocol https certificate", 2),
    ]

    _RE_BGP_INFO = re.compile(
        r"BGP neighbor is (?P<neighbor>.*?), remote AS (?P<as>.*?), .*"
    )  # noqa
    _RE_BGP_RID_INFO = re.compile(
        r".*BGP version 4, remote router ID (?P<rid>.*?), VRF (?P<vrf>.*?)$"
    )  # noqa
    _RE_BGP_DESC = re.compile(r"\s+Description: (?P<description>.*?)$")
    _RE_BGP_LOCAL = re.compile(r"Local AS is (?P<as>.*?),.*")
    _RE_BGP_PREFIX = re.compile(
        r"(\s*?)(?P<af>IPv[46]) (Unicast|6PE):\s*(?P<sent>\d+)\s*(?P<received>\d+)"
    )  # noqa
    _RE_SNMP_COMM = re.compile(
        r"""^snmp-server\s+community\s+(?P<community>\S+)
                                (\s+view\s+(?P<view>\S+))?(\s+(?P<access>ro|rw)?)
                                (\s+ipv6\s+(?P<v6_acl>\S+))?(\s+(?P<v4_acl>\S+))?$""",
        re.VERBOSE,
    )

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize EOS Driver.

        Optional args:
            * lock_disable (True/False): force configuration lock to be disabled (for external lock
                management).
            * enable_password (True/False): Enable password for privilege elevation
            * eos_autoComplete (True/False): Allow for shortening of cli commands
            * transport (string): pyeapi transport, defaults to eos_transport if set
                - socket
                - http_local
                - http
                - https
                - https_certs
                (from: https://github.com/arista-eosplus/pyeapi/blob/develop/pyeapi/client.py#L115)
                transport is the preferred method
            * eos_transport (string): pyeapi transport, defaults to https
                eos_transport for backwards compatibility

        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_session = None
        self.locked = False

        self.platform = "eos"
        self.profile = [self.platform]

        self._process_optional_args(optional_args or {})

    def _process_optional_args(self, optional_args):
        # Define locking method
        self.lock_disable = optional_args.get("lock_disable", False)

        self.enablepwd = optional_args.pop("enable_password", "")
        self.eos_autoComplete = optional_args.pop("eos_autoComplete", None)
        # eos_transport is there for backwards compatibility, transport is the preferred method
        transport = optional_args.get(
            "transport", optional_args.get("eos_transport", "https")
        )
        try:
            self.transport_class = pyeapi.client.TRANSPORTS[transport]
        except KeyError:
            raise ConnectionException("Unknown transport: {}".format(self.transport))
        init_args = inspect.getfullargspec(self.transport_class.__init__)[0]
        init_args.pop(0)  # Remove "self"
        init_args.append("enforce_verification")  # Not an arg for unknown reason

        filter_args = ["host", "username", "password", "timeout", "lock_disable"]

        self.eapi_kwargs = {
            k: v
            for k, v in optional_args.items()
            if k in init_args and k not in filter_args
        }

    def open(self):
        try:
            connection = self.transport_class(
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                **self.eapi_kwargs
            )

            if self.device is None:
                self.device = pyeapi.client.Node(connection, enablepwd=self.enablepwd)
            # does not raise an Exception if unusable

            # let's try to run a very simple command
            self.device.run_commands(["show clock"], encoding="text")
        except ConnectionError as ce:
            # and this is raised either if device not avaiable
            # either if HTTP(S) agent is not enabled
            # show management api http-commands
            raise ConnectionException(str(ce))

    def close(self):
        self.discard_config()

    def is_alive(self):
        return {"is_alive": True}  # always true as eAPI is HTTP-based

    def _lock(self):
        sess = self.device.run_commands(["show configuration sessions"])[0]["sessions"]
        if [
            k
            for k, v in sess.items()
            if v["state"] == "pending" and k != self.config_session
        ]:
            raise SessionLockedException("Session is already in use")

    @staticmethod
    def _multiline_convert(config, start="banner login", end="EOF", depth=1):
        """Converts running-config HEREDOC into EAPI JSON dict"""
        ret = list(config)  # Don't modify list in-place
        try:
            s = ret.index(start)
            e = s
            while depth:
                e = ret.index(end, e + 1)
                depth = depth - 1
        except ValueError:  # Couldn't find end, abort
            return ret
        ret[s] = {"cmd": ret[s], "input": "\n".join(ret[s + 1 : e])}
        del ret[s + 1 : e + 1]

        return ret

    @staticmethod
    def _mode_comment_convert(commands):
        """
        EOS has the concept of multi-line mode comments, shown in the running-config
        as being inside a config stanza (router bgp, ACL definition, etc) and beginning
        with the normal level of spaces and '!!', followed by comments.

        Unfortunately, pyeapi does not accept mode comments in this format, and have to be
        converted to a specific type of pyeapi call that accepts multi-line input

        Copy the config list into a new return list, converting consecutive lines starting with
        "!!" into a single multiline comment command

        :param commands: List of commands to be sent to pyeapi
        :return: Converted list of commands to be sent to pyeapi
        """

        ret = []
        comment_count = 0
        for idx, element in enumerate(commands):
            # Check first for stringiness, as we may have dicts in the command list already
            if isinstance(element, str) and element.startswith("!!"):
                comment_count += 1
                continue
            else:
                if comment_count > 0:
                    # append the previous comment
                    ret.append(
                        {
                            "cmd": "comment",
                            "input": "\n".join(
                                map(
                                    lambda s: s.lstrip("! "),
                                    commands[idx - comment_count : idx],
                                )
                            ),
                        }
                    )
                    comment_count = 0
                ret.append(element)

        return ret

    def _load_config(self, filename=None, config=None, replace=True):
        if self.config_session is None:
            self.config_session = "incendio_{}".format(datetime.now().microsecond)

        commands = []
        commands.append("configure session {}".format(self.config_session))
        if replace:
            commands.append("rollback clean-config")

        if filename is not None:
            with open(filename, "r") as f:
                lines = f.readlines()
        else:
            if isinstance(config, list):
                lines = config
            else:
                lines = config.splitlines()

        for line in lines:
            line = line.strip()
            if line == "":
                continue
            if line.startswith("!") and not line.startswith("!!"):
                continue
            commands.append(line)

        for start, depth in [
            (s, d) for (s, d) in self.HEREDOC_COMMANDS if s in commands
        ]:
            commands = self._multiline_convert(commands, start=start, depth=depth)

        commands = self._mode_comment_convert(commands)

        try:
            if self.eos_autoComplete is not None:
                self.device.run_commands(commands, autoComplete=self.eos_autoComplete)
            else:
                self.device.run_commands(commands)
        except pyeapi.eapilib.CommandError as e:
            self.discard_config()
            msg = str(e)
            if replace:
                raise ReplaceConfigException(msg)
            else:
                raise MergeConfigException(msg)

    def load_replace_candidate(self, filename=None, config=None):
        self._load_config(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        self._load_config(filename, config, False)

    def compare_config(self):
        if self.config_session is None:
            return ""
        else:
            commands = ["show session-config named %s diffs" % self.config_session]
            result = self.device.run_commands(commands, encoding="text")[0]["output"]

            result = "\n".join(result.splitlines()[2:])

            return result.strip()

    def commit_config(self, message=""):
        if not self.lock_disable:
            self._lock()
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        commands = [
            "copy startup-config flash:rollback-0",
            "configure session {}".format(self.config_session),
            "commit",
            "write memory",
        ]

        self.device.run_commands(commands)
        self.config_session = None

    def discard_config(self):
        if self.config_session is not None:
            commands = ["configure session {}".format(self.config_session), "abort"]
            self.device.run_commands(commands)
            self.config_session = None

    def rollback(self):
        commands = ["configure replace flash:rollback-0", "write memory"]
        self.device.run_commands(commands)

    def cli(self, commands):
        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                cli_output[str(command)] = self.device.run_commands(
                    [command], encoding="text"
                )[0].get("output")
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[str(command)] = 'Invalid command: "{cmd}"'.format(
                    cmd=command
                )
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd=command, err=e
                )
                cli_output[str(command)] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_config(self, retrieve="all", full=False):
        """get_config implementation for EOS."""
        get_startup = retrieve == "all" or retrieve == "startup"
        get_running = retrieve == "all" or retrieve == "running"
        get_candidate = (
            retrieve == "all" or retrieve == "candidate"
        ) and self.config_session

        # EOS only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve == "all":
            commands = ["show startup-config", "show running-config{}".format(run_full)]

            if self.config_session:
                commands.append(
                    "show session-config named {}".format(self.config_session)
                )

            output = self.device.run_commands(commands, encoding="text")
            return {
                "startup": str(output[0]["output"]) if get_startup else "",
                "running": str(output[1]["output"]) if get_running else "",
                "candidate": str(output[2]["output"]) if get_candidate else "",
            }
        elif get_startup or get_running:
            if retrieve == "running":
                commands = ["show {}-config{}".format(retrieve, run_full)]
            elif retrieve == "startup":
                commands = ["show {}-config".format(retrieve)]
            output = self.device.run_commands(commands, encoding="text")
            return {
                "startup": str(output[0]["output"]) if get_startup else "",
                "running": str(output[0]["output"]) if get_running else "",
                "candidate": "",
            }
        elif get_candidate:
            commands = ["show session-config named {}".format(self.config_session)]
            output = self.device.run_commands(commands, encoding="text")
            return {"startup": "", "running": "", "candidate": str(output[0]["output"])}
        elif retrieve == "candidate":
            # If we get here it means that we want the candidate but there is none.
            return {"startup": "", "running": "", "candidate": ""}
        else:
            raise Exception("Wrong retrieve filter: {}".format(retrieve))
