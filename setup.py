"""
Packaging for CloudGuard.

The thing worth noting here is the extras_require split. The three cloud SDKs
are heavy and you almost never want all of them at once, so each lives behind
its own extra:

    pip install -e ".[aws]"      # just boto3
    pip install -e ".[azure]"    # just the azure libraries
    pip install -e ".[gcp]"      # just the google client
    pip install -e ".[all]"      # everything, for hacking on the tool itself

Only PyYAML is a hard dependency, because parsing rules is the one thing every
run does no matter which provider you point it at.

The console_scripts entry point is what turns `cloudguard ...` into a real
command on your PATH after install, instead of having to type the longer
`python -m cloudguard.cli`.
"""

from pathlib import Path

from setuptools import find_packages, setup


# Read the long description straight from the README so PyPI / GitHub and the
# package metadata never drift apart.
ROOT = Path(__file__).parent
long_description = (ROOT / "README.md").read_text(encoding="utf-8")


# Pull the version out of the package rather than hard-coding it twice. We read
# the file as text instead of importing it so setup doesn't need the deps
# installed just to find the version string.
version = "0.1.0"
for line in (ROOT / "cloudguard" / "__init__.py").read_text().splitlines():
    if line.startswith("__version__"):
        # line looks like: __version__ = "0.1.0"
        version = line.split("=", 1)[1].strip().strip('"').strip("'")
        break


setup(
    name="cloudguard",
    version=version,
    description="Multi-cloud IAM misconfiguration scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Adrian Korwel",
    url="https://github.com/adriank31/cloudguard",
    license="MIT",
    packages=find_packages(exclude=("tests",)),
    # The rule YAML lives inside the package and has to ship with it, otherwise
    # an installed copy would have no rules to run. include_package_data plus the
    # package_data glob makes sure the .yaml files come along.
    include_package_data=True,
    package_data={"cloudguard": ["rules/*.yaml"]},
    python_requires=">=3.9",
    install_requires=["PyYAML>=6.0"],
    extras_require={
        "aws": ["boto3>=1.26"],
        "azure": ["azure-identity>=1.12", "azure-mgmt-authorization>=3.0"],
        "gcp": ["google-api-python-client>=2.70"],
        # Dev/all bundle, handy when working on the tool itself.
        "all": [
            "boto3>=1.26",
            "azure-identity>=1.12",
            "azure-mgmt-authorization>=3.0",
            "google-api-python-client>=2.70",
            "pytest>=7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cloudguard=cloudguard.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
