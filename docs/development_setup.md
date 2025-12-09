# Setting Up the Development Environment

This guide provides instructions for setting up a development environment for Aerleon.

## Prerequisites

Before starting, ensure you have the following installed:
- [Python 3.10+](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/)

## Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/aerleon/aerleon.git
   cd aerleon
   ```

2. **Install Dependencies**
   Use Poetry to install all required dependencies.
   ```bash
   poetry install
   ```

4. **Run Tests**
   Verify the setup by running the test suite.
   ```bash
   poetry run pytest
   ```

5. **Activate Pre-Commit Hooks**
   Set up pre-commit hooks to ensure code quality.
   ```bash
   poetry run pre-commit install
   ```

6. **Start Development**
   You are now ready to start contributing to Aerleon. Make sure to follow the [contributing guidelines](contributing.md).

## Troubleshooting

- If you encounter issues with Poetry, refer to the [Poetry documentation](https://python-poetry.org/docs/).

## Using the Devcontainer

Aerleon provides a development container to simplify the setup process. Follow these steps to use it:

1. **Open the Project in VS Code**
   Ensure you have the [Remote - Containers](https://code.visualstudio.com/docs/remote/containers) extension installed.

2. **Reopen in Container**
   - Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P` on macOS).
   - Select `Remote-Containers: Reopen in Container`.

3. **Wait for Setup**
   VS Code will build the container and install all dependencies automatically. This may take a few minutes.

4. **Start Developing**
   Once the container is ready, you can start developing immediately. All tools and dependencies are pre-installed.