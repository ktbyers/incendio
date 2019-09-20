# -*- coding: utf-8 -*-
"""
NAPALM CLI Tools: helpers
=========================

Defines helpers for the CLI tools.
"""
# stdlib
import ast
import logging
import sys


def configure_logging(logger, debug):
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


def parse_optional_args(optional_args):
    if optional_args is not None:
        return {
            x.split("=")[0]: ast.literal_eval(x.split("=")[1])
            for x in optional_args.split(",")
        }
    return {}
