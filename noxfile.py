"""Define nox sessions for Aerleon"""

import os
from datetime import datetime

import nox
from nox_poetry import Session, session

nox.options.error_on_missing_interpreters = False
nox.options.reuse_existing_virtualenvs = True
nox.options.sessions = ['test']


@session(python=["3.10", "3.11", "3.12", "3.13", "3.14", "python3.14t"])
def test(session):
    """Runs pytest"""
    session.run_always("poetry", "install", external=True)
    session.run("pytest", "--durations=20")


@session(python="3.13")
def coverage(session):
    """Runs pytest and generates the code coverage report"""
    session.run_always("poetry", "install", external=True)
    session.run("coverage", "run")
    session.run("coverage", "report")
    session.run("coverage", "html")
    session.run("coverage", "xml")


@session(python="3.13")
def benchmark(session):
    """Runs pyperf and produces a report"""
    session.run_always("poetry", "install", external=True)
    tune_system = '__benchmark_tune' in session.posargs
    suite_name = 'SampleSuiteV1'
    benchmark_result_path = './benchmark_result'
    start_time = datetime.now().strftime("%Y-%m-%d-%H.%M.%S")
    result_filename_base = f'{suite_name}-result-{"tuned-" if tune_system else ""}{start_time}'
    result_filename = f'{result_filename_base}.json'
    result_meta_filename = f'{result_filename_base}-metadata.json'
    session.run(
        "python",
        "-c",
        f"import os; os.makedirs('{benchmark_result_path}', exist_ok=True)",
    )

    def inner():
        setup = f'from benchmarks.demo_benchmark import {suite_name}; suite = {suite_name}({session.posargs})'  # noqa E501
        statement = 'suite.run()'

        session.run(
            "pyperf",
            "timeit",
            "--quiet",
            "--stats",
            "--metadata",
            "--copy-env",
            "--no-locale",
            f"--output={os.path.join(benchmark_result_path, result_filename)}",
            "--setup",
            setup,
            statement,
        )
        end_time = datetime.now().strftime("%Y-%m-%d-%H.%M.%S")
        session.run(
            "python",
            "-c",
            f"with open('{os.path.join(benchmark_result_path, result_meta_filename)}', 'x') as file: print('file={result_filename} suite_name={suite_name} tune_system={tune_system} start_time={start_time} end_time={end_time} posargs={session.posargs}', file=file)",  # noqa E501
        )

    if tune_system:
        session.run("pyperf", "system", "tune")
        try:
            inner()
        finally:
            session.run("pyperf", "system", "reset")
    else:
        inner()


@session(python="3.13")
def benchmark_tuned(session):
    """Runs pyperf with system tuning on and produces a report"""
    session.notify('benchmark', ['__benchmark_tune'])


@session
def format(session):
    """Runs black and isort"""
    session.run_always("poetry", "install", external=True)
    session.run("black", "aerleon", "tests")
    session.run("isort", ".")


@session
def lint(session):
    """Runs flake8 and other pre-commit linter hooks"""
    session.run_always("poetry", "install", external=True)
    session.run("pre-commit", "run")


@session
def dev_setup(session: Session) -> None:
    """Installs pre-commit hooks using pre-commit"""
    session.run("pre-commit", "install")
    session.run("git", "config", "blame.ignoreRevsFile", ".git-blame-ignore-revs")
