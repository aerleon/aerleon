""" Define nox sessions for Aerleon """

import nox
from nox_poetry import session, Session


nox.options.error_on_missing_interpreters = False
nox.options.reuse_existing_virtualenvs = True
nox.options.sessions = ['test']


@session(python=["3.7", "3.8", "3.9", "3.10"])
def test(session):
    """Runs pytest"""
    session.run_always("poetry", "install", external=True)
    session.run("pytest", "--durations=20")


@session(python="3.10")
def coverage(session):
    """Runs pytest and generates the code coverage report"""
    session.run_always("poetry", "install", external=True)
    session.run("coverage", "run")
    session.run("coverage", "report")
    session.run("coverage", "html")


@session
def format(session):
    """Runs black"""
    session.run_always("poetry", "install", external=True)
    session.run("black", "aerleon", "tests")


@session
def lint(session):
    """Runs flake8 and other pre-commit linter hooks"""
    session.run_always("poetry", "install", external=True)
    session.run("pre-commit", "run")


@session
def dev_setup(session: Session) -> None:
    """Installs pre-commit hooks using pre-commit"""
    session.run("pre-commit", "install")
