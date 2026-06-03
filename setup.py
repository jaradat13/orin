# setup.py
from setuptools import setup

setup(
    name="orin-engine",
    version="0.1.0",
    author="Musa Jaradat",
    author_email="musa@debian",
    description="Fully offline local system forensics investigation engine.",
    python_requires=">=3.10",
    packages=[
        "orin",
        "orin.core",
        "orin.collectors",
        "orin.analysis"
    ],
    package_dir={
        "orin": ".",
        "orin.core": "core",
        "orin.collectors": "collectors",
        "orin.analysis": "analysis"
    },
    install_requires=["psutil>=5.9.0"],
    entry_points={
        "console_scripts": [
            "orin=orin.main:main",
        ],
    },
)
