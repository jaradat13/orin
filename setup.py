# setup.py
from setuptools import setup, find_packages

setup(
    name="orin-engine",
    version="0.1.0",
    author="Musa Jaradat",
    author_email="musa@debian",
    description="Fully offline local system forensics investigation engine.",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[],
    entry_points={
        "console_scripts": [
            "orin=orin.main:main",
        ],
    },
)
