from setuptools import setup, find_packages

setup(
    name="NetInspector",
    version="1.0.0",
    description="Port Scanner Tool",
    author="Hariom Singh",
    author_email="hariomsingh0398@gmail.com",
    url="https://github.com/Hari0mSingh/NetInspector-PortScanner",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.1",
        "scapy-python3>=2.5.0",
        "tabulate>=0.9.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "netinspector=scan:cli",
        ],
    },
)