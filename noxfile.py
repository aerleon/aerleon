""" Define nox sessions for Aerleon """

import os
import pathlib

import nox


nox.options.error_on_missing_interpreters = True
nox.options.reuse_existing_virtualenvs = True
nox.options.sessions = ['test']


@nox.session(python=["3.7", "3.8", "3.9", "3.10"])
def test(session):
    """Runs pytest"""
    session.install(".[test]")
    session.run("pytest", "--durations=20")


@nox.session(python="3.10")
def coverage(session):
    """Runs pytest and generates the code coverage report"""
    session.install(".[coverage]")
    session.run("coverage", "run")
    session.run("coverage", "report")
    session.run("coverage", "html")


@nox.session
def format(session):
    """Runs black"""
    session.install(".[dev]")
    session.run("black", "aerleon", "tests")


@nox.session
def lint(session):
    """Runs flake8 and other pre-commit linter hooks"""
    session.install(".[dev]")
    session.run("pre-commit", "run")


VENV_DIR = pathlib.Path('./.venv').resolve()


@nox.session
def dev_setup(session: nox.Session) -> None:
    """
    Sets up a python development environment for the project.

    This session will:
    - Create a python virtualenv for the session
    - Install the `virtualenv` cli tool into this environment
    - Use `virtualenv` to create a global project virtual environment
    - Invoke the python interpreter from the global project environment to install
      the project and all it's development dependencies.
    """

    session.install("virtualenv")
    # the VENV_DIR constant is explained above
    session.run("virtualenv", os.fsdecode(VENV_DIR), silent=True)

    python = os.fsdecode(VENV_DIR.joinpath("bin/python"))

    # Use the venv's interpreter to install the project along with
    # all it's dev dependencies, this ensures it's installed in the right way
    session.run(python, "-m", "pip", "install", "-e", ".[dev]", external=True)
    session.run(python, "-m", "pre-commit", "install")
