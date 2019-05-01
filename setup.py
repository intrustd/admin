# Always prefer setuptools over distutils
from setuptools import setup, find_packages
from os import path

setup(
    name="intrustd-admin",
    version="0.1.0",
    description="Intrustd Admin App",
    packages=find_packages(),
    install_requires=["Flask>=0.2", "celery", "redis", "Pillow"],
    entry_points={
        'console_scripts': [ 'intrustd-admin=intrustd.admin:main' ]
    }
)
