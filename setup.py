# setup.py
from setuptools import setup, find_packages

setup(
    name="orin",
    version="1.0.0",
    author="Musa Jaradat",
    author_email="jaradat.musa@gmail.com",
    description="Fully offline local system forensics investigation engine.",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "orin.core": ["dashboard.html"],
    },
    install_requires=[],
    entry_points={
        "console_scripts": [
            "orin=orin.main:main",
        ],
    },
)
