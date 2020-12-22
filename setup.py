import pathlib
import runpy

from setuptools import find_packages, setup


base_directory = pathlib.Path(__file__).resolve().parent
version = runpy.run_path(base_directory / "lampions" / "version.py")


def parse_requirements_file(filename):
    return pathlib.Path(filename).read_text().splitlines()


if __name__ == "__main__":
    install_requires = parse_requirements_file("requirements.txt")

    with open(base_directory / "README.md") as f:
        long_description = f.read()

    setup(
        name="lampions",
        version=version["__version__"],
        install_requires=install_requires,
        description=("Command-line utility to configure Lampions and manage "
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
