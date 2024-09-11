from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sniperpy",
    version="1.0.1",
    author="Ankit Dobhal",
    author_email="dobhal.ankit@protonmail.com",
    description="A Python package to analyze SMB2 packets from pcap files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/powerexploit/sniper",
    project_urls={
        "Bug Tracker": "https://github.com/powerexploit/sniper/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "scapy", 
    ],
    entry_points={
        'console_scripts': [
            'sniperpy=smb_extractor:main',
        ],
    },
)
