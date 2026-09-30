from setuptools import setup, find_packages

setup(
    name="emla",
    version="0.1.0",
    description="Error Message Linguistics Analyzer (EMLA) - Security Analysis & Information Leakage Scoring Tool",
    author="EMLA Security Team",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "emla=emla.cli:main",
        ],
    },
    python_requires=">=3.8",
)
