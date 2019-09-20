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

"""Driver for JunOS devices."""

from __future__ import unicode_literals

# import stdlib
import re
import json
import logging
from collections import OrderedDict

# import third party lib
from lxml import etree

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import ConnectTimeoutError
from jnpr.junos.exception import LockError as JnprLockError
from jnpr.junos.exception import UnlockError as JnrpUnlockError

# import Incendio Base
from incendio.base.base import NetworkDriver
from incendio.base.utils import py23_compat
from incendio.base.exceptions import ConnectionException
from incendio.base.exceptions import MergeConfigException
from incendio.base.exceptions import ReplaceConfigException
from incendio.base.exceptions import LockError
from incendio.base.exceptions import UnlockError


log = logging.getLogger(__file__)


class JunOSDriver(NetworkDriver):
    """JunOSDriver class - inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialise JunOS driver.

        Optional args:
            * config_lock (True/False): lock configuration DB after the connection is established.
            * lock_disable (True/False): force configuration lock to be disabled (for external lock
                management).
            * port (int): custom port
            * key_file (string): SSH key file path
            * keepalive (int): Keepalive interval
            * ignore_warning (boolean): not generate warning exceptions
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_replace = False
        self.locked = False

        # Get optional arguments
        if optional_args is None:
            optional_args = {}

        self.port = optional_args.get("port", 22)
        self.key_file = optional_args.get("key_file", None)
        self.keepalive = optional_args.get("keepalive", 30)
        self.ssh_config_file = optional_args.get("ssh_config_file", None)
        self.ignore_warning = optional_args.get("ignore_warning", False)

        # Define locking method
        self.lock_disable = optional_args.get("lock_disable", False)
        self.session_config_lock = optional_args.get("config_lock", False)

        # Junos driver specific options
        self.junos_config_database = optional_args.get(
            "junos_config_database", "committed"
        )

        if self.key_file:
            self.device = Device(
                hostname,
                user=username,
                password=password,
                ssh_private_key_file=self.key_file,
                ssh_config=self.ssh_config_file,
                port=self.port,
            )
        else:
            self.device = Device(
                hostname,
                user=username,
                password=password,
                port=self.port,
                ssh_config=self.ssh_config_file,
            )

        self.platform = "junos"
        self.profile = [self.platform]

    def open(self):
        """Open the connection with the device."""
        try:
            self.device.open()
        except ConnectTimeoutError as cte:
            raise ConnectionException(cte.msg)
        self.device.timeout = self.timeout
        self.device._conn._session.transport.set_keepalive(self.keepalive)
        if hasattr(self.device, "cu"):
            # make sure to remove the cu attr from previous session
            # ValueError: requested attribute name cu already exists
            del self.device.cu
        self.device.bind(cu=Config)
        if not self.lock_disable and self.session_config_lock:
            self._lock()

    def close(self):
        """Close the connection."""
        if not self.lock_disable and self.session_config_lock:
            self._unlock()
        self.device.close()

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            try:
                self.device.cu.lock()
                self.locked = True
            except JnprLockError as jle:
                raise LockError(py23_compat.text_type(jle))

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            try:
                self.device.cu.unlock()
                self.locked = False
            except JnrpUnlockError as jue:
                raise UnlockError(jue)

    def _rpc(self, get, child=None, **kwargs):
        """
        This allows you to construct an arbitrary RPC call to retreive common stuff. For example:
        Configuration:  get: "<get-configuration/>"
        Interface information:  get: "<get-interface-information/>"
        A particular interfacece information:
              get: "<get-interface-information/>"
              child: "<interface-name>ge-0/0/0</interface-name>"
        """
        rpc = etree.fromstring(get)

        if child:
            rpc.append(etree.fromstring(child))

        response = self.device.execute(rpc)
        return etree.tostring(response)

    def is_alive(self):
        # evaluate the state of the underlying SSH connection
        # and also the NETCONF status from PyEZ
        return {
            "is_alive": self.device._conn._session.transport.is_active()
            and self.device.connected
        }

    @staticmethod
    def _is_json_format(config):
        try:
            _ = json.loads(config)  # noqa
        except (TypeError, ValueError):
            return False
        return True

    def _detect_config_format(self, config):
        fmt = "text"
        set_action_matches = [
            "set",
            "activate",
            "deactivate",
            "annotate",
            "copy",
            "delete",
            "insert",
            "protect",
            "rename",
            "unprotect",
            "edit",
            "top",
        ]
        if config.strip().startswith("<"):
            return "xml"
        elif config.strip().split(" ")[0] in set_action_matches:
            return "set"
        elif self._is_json_format(config):
            return "json"
        return fmt

    def _load_candidate(self, filename, config, overwrite):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        if not self.lock_disable and not self.session_config_lock:
            # if not locked during connection time, will try to lock
            self._lock()

        try:
            fmt = self._detect_config_format(configuration)

            if fmt == "xml":
                configuration = etree.XML(configuration)

            self.device.cu.load(
                configuration,
                format=fmt,
                overwrite=overwrite,
                ignore_warning=self.ignore_warning,
            )
        except ConfigLoadError as e:
            if self.config_replace:
                raise ReplaceConfigException(e.errs)
            else:
                raise MergeConfigException(e.errs)

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        self.config_replace = True
        self._load_candidate(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        self.config_replace = False
        self._load_candidate(filename, config, False)

    def compare_config(self):
        """Compare candidate config with running."""
        diff = self.device.cu.diff()

        if diff is None:
            return ""
        else:
            return diff.strip()

    def commit_config(self, message=""):
        """Commit configuration."""
        commit_args = {"comment": message} if message else {}
        self.device.cu.commit(ignore_warning=self.ignore_warning, **commit_args)
        if not self.lock_disable and not self.session_config_lock:
            self._unlock()

    def discard_config(self):
        """Discard changes (rollback 0)."""
        self.device.cu.rollback(rb_id=0)
        if not self.lock_disable and not self.session_config_lock:
            self._unlock()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def cli(self, commands):
        """Execute raw CLI commands and returns their output."""
        cli_output = {}

        def _count(txt, none):  # Second arg for consistency only. noqa
            """
            Return the exact output, as Junos displays
            e.g.:
            > show system processes extensive | match root | count
            Count: 113 lines
            """
            count = len(txt.splitlines())
            return "Count: {count} lines".format(count=count)

        def _trim(txt, length):
            """
            Trim specified number of columns from start of line.
            """
            try:
                newlines = []
                for line in txt.splitlines():
                    newlines.append(line[int(length) :])
                return "\n".join(newlines)
            except ValueError:
                return txt

        def _except(txt, pattern):
            """
            Show only text that does not match a pattern.
            """
            rgx = "^.*({pattern}).*$".format(pattern=pattern)
            unmatched = [
                line for line in txt.splitlines() if not re.search(rgx, line, re.I)
            ]
            return "\n".join(unmatched)

        def _last(txt, length):
            """
            Display end of output only.
            """
            try:
                return "\n".join(txt.splitlines()[(-1) * int(length) :])
            except ValueError:
                return txt

        def _match(txt, pattern):
            """
            Show only text that matches a pattern.
            """
            rgx = "^.*({pattern}).*$".format(pattern=pattern)
            matched = [line for line in txt.splitlines() if re.search(rgx, line, re.I)]
            return "\n".join(matched)

        def _find(txt, pattern):
            """
            Search for first occurrence of pattern.
            """
            rgx = "^.*({pattern})(.*)$".format(pattern=pattern)
            match = re.search(rgx, txt, re.I | re.M | re.DOTALL)
            if match:
                return "{pattern}{rest}".format(pattern=pattern, rest=match.group(2))
            else:
                return "\nPattern not found"

        def _process_pipe(cmd, txt):
            """
            Process CLI output from Juniper device that
            doesn't allow piping the output.
            """
            if txt is None:
                return txt
            _OF_MAP = OrderedDict()
            _OF_MAP["except"] = _except
            _OF_MAP["match"] = _match
            _OF_MAP["last"] = _last
            _OF_MAP["trim"] = _trim
            _OF_MAP["count"] = _count
            _OF_MAP["find"] = _find
            # the operations order matter in this case!
            exploded_cmd = cmd.split("|")
            pipe_oper_args = {}
            for pipe in exploded_cmd[1:]:
                exploded_pipe = pipe.split()
                pipe_oper = exploded_pipe[0]  # always there
                pipe_args = "".join(exploded_pipe[1:2])
                # will not throw error when there's no arg
                pipe_oper_args[pipe_oper] = pipe_args
            for oper in _OF_MAP.keys():
                # to make sure the operation sequence is correct
                if oper not in pipe_oper_args.keys():
                    continue
                txt = _OF_MAP[oper](txt, pipe_oper_args[oper])
            return txt

        if not isinstance(commands, list):
            raise TypeError("Please enter a valid list of commands!")
        _PIPE_BLACKLIST = ["save"]
        # Preprocessing to avoid forbidden commands
        for command in commands:
            exploded_cmd = command.split("|")
            command_safe_parts = []
            for pipe in exploded_cmd[1:]:
                exploded_pipe = pipe.split()
                pipe_oper = exploded_pipe[0]  # always there
                if pipe_oper in _PIPE_BLACKLIST:
                    continue
                pipe_args = "".join(exploded_pipe[1:2])
                safe_pipe = (
                    pipe_oper
                    if not pipe_args
                    else "{fun} {args}".format(fun=pipe_oper, args=pipe_args)
                )
                command_safe_parts.append(safe_pipe)
            safe_command = (
                exploded_cmd[0]
                if not command_safe_parts
                else "{base} | {pipes}".format(
                    base=exploded_cmd[0], pipes=" | ".join(command_safe_parts)
                )
            )
            raw_txt = self.device.cli(safe_command, warning=False)
            cli_output[py23_compat.text_type(command)] = py23_compat.text_type(
                _process_pipe(command, raw_txt)
            )
        return cli_output

    def get_config(self, retrieve="all", full=False):
        rv = {"startup": "", "running": "", "candidate": ""}

        options = {"format": "text", "database": "candidate"}

        if retrieve in ("candidate", "all"):
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv["candidate"] = py23_compat.text_type(config.text)
        if retrieve in ("running", "all"):
            options["database"] = "committed"
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv["running"] = py23_compat.text_type(config.text)
        return rv
