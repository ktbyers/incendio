"""Helper functions for the Incendio base."""

# std libs
import os
import re
import sys
import itertools

# third party libs
import jinja2
import textfsm
from netaddr import EUI
from netaddr import mac_unix
from netaddr import IPAddress

# local modules
import incendio.base.exceptions
from incendio.base.utils.jinja_filters import CustomJinjaFilters
from incendio.base.utils import py23_compat
from incendio.base.canonical_map import base_interfaces, reverse_mapping


# ----------------------------------------------------------------------------------------------------------------------
# helper classes -- will not be exported
# ----------------------------------------------------------------------------------------------------------------------
class _MACFormat(mac_unix):
    pass


_MACFormat.word_fmt = "%.2X"


# ----------------------------------------------------------------------------------------------------------------------
# callable helpers
# ----------------------------------------------------------------------------------------------------------------------
def load_template(
    cls,
    template_name,
    template_source=None,
    template_path=None,
    openconfig=False,
    jinja_filters={},
    **template_vars
):
    try:
        search_path = []
        if isinstance(template_source, py23_compat.string_types):
            template = jinja2.Template(template_source)
        else:
            if template_path is not None:
                if (
                    isinstance(template_path, py23_compat.string_types)
                    and os.path.isdir(template_path)
                    and os.path.isabs(template_path)
                ):
                    # append driver name at the end of the custom path
                    search_path.append(
                        os.path.join(template_path, cls.__module__.split(".")[-1])
                    )
                else:
                    raise IOError(
                        "Template path does not exist: {}".format(template_path)
                    )
            else:
                # Search modules for template paths
                search_path = [
                    os.path.dirname(os.path.abspath(sys.modules[c.__module__].__file__))
                    for c in cls.__class__.mro()
                    if c is not object
                ]

            if openconfig:
                search_path = ["{}/oc_templates".format(s) for s in search_path]
            else:
                search_path = ["{}/templates".format(s) for s in search_path]

            loader = jinja2.FileSystemLoader(search_path)
            environment = jinja2.Environment(loader=loader)

            for filter_name, filter_function in itertools.chain(
                CustomJinjaFilters.filters().items(), jinja_filters.items()
            ):
                environment.filters[filter_name] = filter_function

            template = environment.get_template(
                "{template_name}.j2".format(template_name=template_name)
            )
        configuration = template.render(**template_vars)
    except jinja2.exceptions.TemplateNotFound:
        raise incendio.base.exceptions.TemplateNotImplemented(
            "Config template {template_name}.j2 not found in search path: {sp}".format(
                template_name=template_name, sp=search_path
            )
        )
    except (
        jinja2.exceptions.UndefinedError,
        jinja2.exceptions.TemplateSyntaxError,
    ) as jinjaerr:
        raise incendio.base.exceptions.TemplateRenderException(
            "Unable to render the Jinja config template {template_name}: {error}".format(
                template_name=template_name, error=py23_compat.text_type(jinjaerr)
            )
        )
    return cls.load_merge_candidate(config=configuration)


def textfsm_extractor(cls, template_name, raw_text):
    """
    Applies a TextFSM template over a raw text and return the matching table.

    Main usage of this method will be to extract data form a non-structured output
    from a network device and return the values in a table format.

    :param cls: Instance of the driver class
    :param template_name: Specifies the name of the template to be used
    :param raw_text: Text output as the devices prompts on the CLI
    :return: table-like list of entries
    """
    textfsm_data = list()
    fsm_handler = None
    for c in cls.__class__.mro():
        if c is object:
            continue
        current_dir = os.path.dirname(
            os.path.abspath(sys.modules[c.__module__].__file__)
        )
        template_dir_path = "{current_dir}/utils/textfsm_templates".format(
            current_dir=current_dir
        )
        template_path = "{template_dir_path}/{template_name}.tpl".format(
            template_dir_path=template_dir_path, template_name=template_name
        )

        try:
            with open(template_path) as f:
                fsm_handler = textfsm.TextFSM(f)

                for obj in fsm_handler.ParseText(raw_text):
                    entry = {}
                    for index, entry_value in enumerate(obj):
                        entry[fsm_handler.header[index].lower()] = entry_value
                    textfsm_data.append(entry)

                return textfsm_data
        except IOError:  # Template not present in this class
            continue  # Continue up the MRO
        except textfsm.TextFSMTemplateError as tfte:
            raise incendio.base.exceptions.TemplateRenderException(
                "Wrong format of TextFSM template {template_name}: {error}".format(
                    template_name=template_name, error=py23_compat.text_type(tfte)
                )
            )

    raise incendio.base.exceptions.TemplateNotImplemented(
        "TextFSM template {template_name}.tpl is not defined under {path}".format(
            template_name=template_name, path=template_dir_path
        )
    )


def mac(raw):
    """
    Converts a raw string to a standardised MAC Address EUI Format.

    :param raw: the raw string containing the value of the MAC Address
    :return: a string with the MAC Address in EUI format

    Example:

    .. code-block:: python

        >>> mac('0123.4567.89ab')
        u'01:23:45:67:89:AB'

    Some vendors like Cisco return MAC addresses like a9:c5:2e:7b:6: which is not entirely valid
    (with respect to EUI48 or EUI64 standards). Therefore we need to stuff with trailing zeros

    Example
    >>> mac('a9:c5:2e:7b:6:')
    u'A9:C5:2E:7B:60:00'

    If Cisco or other obscure vendors use their own standards, will throw an error and we can fix
    later, however, still works with weird formats like:

    >>> mac('123.4567.89ab')
    u'01:23:45:67:89:AB'
    >>> mac('23.4567.89ab')
    u'00:23:45:67:89:AB'
    """
    if raw.endswith(":"):
        flat_raw = raw.replace(":", "")
        raw = "{flat_raw}{zeros_stuffed}".format(
            flat_raw=flat_raw, zeros_stuffed="0" * (12 - len(flat_raw))
        )
    return py23_compat.text_type(EUI(raw, dialect=_MACFormat))


def ip(addr, version=None):
    """
    Converts a raw string to a valid IP address. Optional version argument will detect that \
    object matches specified version.

    Motivation: the groups of the IP addreses may contain leading zeros. IPv6 addresses can \
    contain sometimes uppercase characters. E.g.: 2001:0dB8:85a3:0000:0000:8A2e:0370:7334 has \
    the same logical value as 2001:db8:85a3::8a2e:370:7334. However, their values as strings are \
    not the same.

    :param raw: the raw string containing the value of the IP Address
    :param version: (optional) insist on a specific IP address version.
    :type version: int.
    :return: a string containing the IP Address in a standard format (no leading zeros, \
    zeros-grouping, lowercase)

    Example:

    .. code-block:: python

        >>> ip('2001:0dB8:85a3:0000:0000:8A2e:0370:7334')
        u'2001:db8:85a3::8a2e:370:7334'
    """
    addr_obj = IPAddress(addr)
    if version and addr_obj.version != version:
        raise ValueError("{} is not an ipv{} address".format(addr, version))
    return py23_compat.text_type(addr_obj)
