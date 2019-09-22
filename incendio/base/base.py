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

import sys

from netmiko import ConnectHandler, NetMikoTimeoutException

# local modules
import incendio.base.exceptions
import incendio.base.helpers
from incendio.base.exceptions import ConnectionException


class NetworkDriver(object):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        This is the base class you have to inherit from when writing your own Network Driver to
        manage any device. You will, in addition, have to override all the methods specified on
        this class. Make sure you follow the guidelines for every method and that you return the
        correct data.

        :param hostname: (str) IP or FQDN of the device you want to connect to.
        :param username: (str) Username you want to use
        :param password: (str) Password
        :param timeout: (int) Time in seconds to wait for the device to respond.
        :param optional_args: (dict) Pass additional arguments to underlying driver
        :return:
        """
        raise NotImplementedError

    def __enter__(self):
        try:
            self.open()
            return self
        except:  # noqa: E722
            # Swallow exception if __exit__ returns a True value
            if self.__exit__(*sys.exc_info()):
                pass
            else:
                raise

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()
        if exc_type is not None and (
            exc_type.__name__ not in dir(incendio.base.exceptions)
            and exc_type.__name__ not in __builtins__.keys()
        ):
            epilog = (
                "Incendio didn't catch this exception. Please file a bug on this issue. "
                "Don't forget to include the traceback."
            )
            print(epilog)
            return False

    def __del__(self):
        """
        This method is used to cleanup when the program is terminated suddenly.
        We need to make sure the connection is closed properly and the configuration DB
        is released (unlocked).
        """
        try:
            if self.is_alive()["is_alive"]:
                self.close()
        except Exception:
            pass

    def _netmiko_open(self, device_type, netmiko_optional_args=None):
        """Standardized method of creating a Netmiko connection using Incendio attributes."""
        if netmiko_optional_args is None:
            netmiko_optional_args = {}
        try:
            self._netmiko_device = ConnectHandler(
                device_type=device_type,
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                **netmiko_optional_args
            )
        except NetMikoTimeoutException:
            raise ConnectionException("Cannot connect to {}".format(self.hostname))

        # ensure in enable mode
        self._netmiko_device.enable()
        return self._netmiko_device

    def _netmiko_close(self):
        """Standardized method of closing a Netmiko connection."""
        if getattr(self, "_netmiko_device", None):
            self._netmiko_device.disconnect()
            self._netmiko_device = None
        self.device = None

    def open(self):
        """
        Opens a connection to the device.
        """
        raise NotImplementedError

    def close(self):
        """
        Closes the connection to the device.
        """
        raise NotImplementedError

    def pre_connection_tests(self):
        """
        This is a helper function used by the cli tool cl_napalm. Drivers
        can override this method to do some tests, show information, enable debugging, etc.
        before a connection with the device is attempted.
        """
        raise NotImplementedError

    def connection_tests(self):
        """
        This is a helper function used by the cli tool cl_napalm. Drivers
        can override this method to do some tests, show information, enable debugging, etc.
        before a connection with the device has been successful.
        """
        raise NotImplementedError

    def post_connection_tests(self):
        """
        This is a helper function used by the cli tool cl_napalm. Drivers
        can override this method to do some tests, show information, enable debugging, etc.
        after a connection with the device has been closed successfully.
        """
        raise NotImplementedError

    def load_template(
        self, template_name, template_source=None, template_path=None, **template_vars
    ):
        """
        Will load a templated configuration on the device.

        :param cls: Instance of the driver class.
        :param template_name: Identifies the template name.
        :param template_source (optional): Custom config template rendered and loaded on device
        :param template_path (optional): Absolute path to directory for the configuration templates
        :param template_vars: Dictionary with arguments to be used when the template is rendered.
        :raise DriverTemplateNotImplemented: No template defined for the device type.
        :raise TemplateNotImplemented: The template specified in template_name does not exist in \
        the default path or in the custom path if any specified using parameter `template_path`.
        :raise TemplateRenderException: The template could not be rendered. Either the template \
        source does not have the right format, either the arguments in `template_vars` are not \
        properly specified.
        """
        return incendio.base.helpers.load_template(
            self,
            template_name,
            template_source=template_source,
            template_path=template_path,
            **template_vars
        )

    def load_replace_candidate(self, filename=None, config=None):
        """
        Populates the candidate configuration. You can populate it from a file or from a string.
        If you send both a filename and a string containing the configuration, the file takes
        precedence.

        If you use this method the existing configuration will be replaced entirely by the
        candidate configuration once you commit the changes. This method will not change the
        configuration by itself.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise ReplaceConfigException: If there is an error on the configuration sent.
        """
        raise NotImplementedError

    def load_merge_candidate(self, filename=None, config=None):
        """
        Populates the candidate configuration. You can populate it from a file or from a string.
        If you send both a filename and a string containing the configuration, the file takes
        precedence.

        If you use this method the existing configuration will be merged with the candidate
        configuration once you commit the changes. This method will not change the configuration
        by itself.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise MergeConfigException: If there is an error on the configuration sent.
        """
        raise NotImplementedError

    def compare_config(self):
        """
        :return: A string showing the difference between the running configuration and the \
        candidate configuration. The running_config is loaded automatically just before doing the \
        comparison so there is no need for you to do it.
        """
        raise NotImplementedError

    def commit_config(self, message=""):
        """
        Commits the changes requested by the method load_replace_candidate or load_merge_candidate.
        """
        raise NotImplementedError

    def discard_config(self):
        """
        Discards the configuration loaded into the candidate.
        """
        raise NotImplementedError

    def rollback(self):
        """
        If changes were made, revert changes to the original state.
        """
        raise NotImplementedError

    def cli(self, commands):

        """
        Will execute a list of commands and return the output in a dictionary format.

        Example::

            {
                u'show version and haiku':  u'''Hostname: re0.edge01.arn01
                                                Model: mx480
                                                Junos: 13.3R6.5

                                                        Help me, Obi-Wan
                                                        I just saw Episode Two
                                                        You're my only hope
                                            ''',
                u'show chassis fan'     :   u'''
                    Item               Status  RPM     Measurement
                    Top Rear Fan       OK      3840    Spinning at intermediate-speed
                    Bottom Rear Fan    OK      3840    Spinning at intermediate-speed
                    Top Middle Fan     OK      3900    Spinning at intermediate-speed
                    Bottom Middle Fan  OK      3840    Spinning at intermediate-speed
                    Top Front Fan      OK      3810    Spinning at intermediate-speed
                    Bottom Front Fan   OK      3840    Spinning at intermediate-speed'''
            }
        """
        raise NotImplementedError
