# Always prefer setuptools over distutils
from setuptools import setup, find_packages
from os import path

setup(
    name="kite-admin",
    version="0.1.0",
    description="Kite Admin App",
    packages=find_packages(),
    install_requires=["Flask>=0.2"],
    entry_points={
        'console_scripts': [ 'kite-admin=kite.admin:main' ]
    }
)
