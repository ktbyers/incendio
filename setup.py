"""setup.py file."""
from setuptools import setup, find_packages

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]


__author__ = "Kirk Byers <ktbyers@twb-tech.com>"

setup(
    name="incendio",
    version="3.0.0",
    packages=find_packages(exclude=("test*",)),
    test_suite="test_base",
    author="David Barroso, Kirk Byers, Mircea Ulinic",
    author_email="dbarrosop@dravetech.com, ping@mirceaulinic.net, ktbyers@twb-tech.com",
    description="NAPALM but just for config",
    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    url="https://github.com/ktbyers/incendio",
    include_package_data=True,
    install_requires=reqs,
    entry_points={
        "console_scripts": [
            "cl_napalm_configure=napalm.base.clitools.cl_napalm_configure:main",
            "cl_napalm_test=napalm.base.clitools.cl_napalm_test:main",
            "cl_napalm_validate=napalm.base.clitools.cl_napalm_validate:main",
            "napalm=napalm.base.clitools.cl_napalm:main",
        ]
    },
)
