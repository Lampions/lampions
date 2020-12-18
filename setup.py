import os
import runpy

from setuptools import find_packages, setup

base_dir = os.path.dirname(os.path.abspath(__file__))
lampions = runpy.run_path(os.path.join(base_dir, "lampions", "__init__.py"))


def parse_requirements_file(filename):
    with open(filename) as input_file:
        return input_file.read().splitlines()


if __name__ == "__main__":
    install_requires = parse_requirements_file("requirements.txt")

    with open(os.path.join(base_dir, "README.md")) as f:
        long_description = f.read()

    setup(
        name="Lampions",
        version=lampions["__version__"],
        install_requires=install_requires,
        description=("Command-line utility to configure and control Lampions "
                     "email aliases"),
        url="http://github.com/lampions/lampions",
        author="Niklas Koep",
        author_email="niklas.koep@gmail.com",
        license="BSD 3-Clause",
        long_description=long_description,
        long_description_content_type="text/markdown",
        packages=find_packages(),
        python_requires=">=3.6, <4",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: BSD License",
            "Operating System :: POSIX :: Linux"
        ],
        entry_points={
            "console_scripts": [
                "lampions=lampions:main"
            ]
        }
    )
