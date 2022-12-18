# Contributing to the App


The project is packaged with a light [development environment](dev_environment.md) based on `Docker` to help with the local development of the project and to run tests.

The project is leveraging the following software standards:

- Python linting and formatting: `black`, `flake8`, and `pydocstyle`.

Documentation is built using [mkdocs](https://www.mkdocs.org/). The [Docker based development environment](dev_environment.md#docker-development-environment) automatically starts a container hosting a live version of the documentation website on [http://localhost:8001](http://localhost:8001) that auto-refreshes when you make any changes to your local files.

## Branching Policy

The branching policy includes the following tenets:

- The main branch is the primary branch to source off of.
- If there is a reason to have a patch version, the maintainers may use cherry-picking strategy.
- PRs intended to add new features should be sourced from the main branch.
- PRs intended to address bug fixes and security patches should be sourced from the main branch.
- PRs intended to add new features that break backward compatibility should be discussed before a PR is created.

Aerleon will observe semantic versioning. This may result in an quick turn around in minor versions to keep pace with an ever growing feature set.

TODO: Confirm that main will be primary branch.

## Release Policy

Aerleon has currently no intended scheduled release schedule, and will release new features in minor versions.

When a new release is created the following should happen.

- A release PR is created with:
    - Update to the changelog in `docs/user/release_notes/version_<major>.<minor>.md` file to reflect the changes.
    - Update the `mkdocs.yml` file to reflect the additional page, as applicable.
    - Change the version from `<major>.<minor>.<patch>-beta` to `<major>.<minor>.<patch>` in pyproject.toml.
    - Set the PR to the main
- Ensure the tests for the PR pass.
- Merge the PR.
- Create a new tag:
    - The tag should be in the form of `v<major>.<minor>.<patch>`.
    - The title should be in the form of `v<major>.<minor>.<patch>`.
    - The description should be the changes that were added to the `version_<major>.<minor>.md` document.
- A post release PR is created with.
    - Change the version from `<major>.<minor>.<patch>` to `<major>.<minor>.<patch + 1>-beta` pyproject.toml.
    - Set the PR to the `main`.
    - Once tests pass, merge.
