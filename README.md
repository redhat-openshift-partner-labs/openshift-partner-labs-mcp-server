# OpenShift Partner Labs MCP Server

A Model Context Protocol (MCP) server designed specifically for OpenShift Partner Labs, providing high-level conversational operations for lab managers, administrators, and developers. This server aggregates low-level database interactions into AI-friendly tools that enable natural language workflows.

[![CI Status](https://github.com/redhat-openshift-partner-labs/openshift-partner-labs-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat-openshift-partner-labs/openshift-partner-labs-mcp-server/actions/workflows/ci.yml)
![Project Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

## Features

- **FastAPI-based MCP server** with multiple transport protocol support (HTTP, SSE, Streamable-HTTP)
- **PostgreSQL integration** with connection pooling and async operations
- **OAuth2 authentication** with Red Hat SSO (optional via `ENABLE_AUTH` flag)
- **Container-ready deployment** with Red Hat UBI and OpenShift configurations
- **Comprehensive tool system** for lab management operations
- **Production-ready** with health checks, logging, and monitoring

## Tech Stack

- **Language**: Python 3.12+
- **Framework**: FastAPI with FastMCP (v2.10.4)
- **Database**: PostgreSQL with asyncpg/psycopg2-binary
- **Authentication**: OAuth2 with Red Hat SSO (configurable)
- **Container**: Containerfile optimized for Podman/Red Hat UBI
- **Development Tools**: pytest, ruff, mypy, pre-commit hooks

## Purpose and Philosophy

This server is **not** a traditional REST API that provides a one-to-one mapping of database interactions. Instead, its core philosophy is to **aggregate low-level interactions into high-level, conversational actions** that can be easily used by an AI agent.

The primary goal is to address the challenges of traditional UIs, such as:

* **High development overhead:** Reducing the developer "cycles" needed for UI changes.
* **Developer dependency:** Empowering users to perform routine operational tasks (like changing a cluster's state) via the agent without needing a developer.
* **Complex workflows:** Simplifying processes like cluster provisioning into guided, natural language conversations.

Developers contributing to this server should always consider if they are providing a tool, prompt, or resource that empowers the agent to fulfill a high-level user request, rather than simply exposing a raw backend function.

## Architecture

This server functions as the critical **API Layer** in the AI-driven architecture, connecting conversational agents with OpenShift Partner Labs infrastructure.

```
[User] <--> [Chat Interface] <--> [AI Agent] <--> [MCP Server] <--> [PostgreSQL Database]
                                                       |
                                                   [OAuth2/SSO]
                                                       |
                                                [Storage Service]
```

### Components

- **MCP Server**: FastAPI-based server with multiple transport protocols
- **PostgreSQL Database**: Primary data store with connection pooling
- **OAuth2/SSO**: Red Hat SSO integration (configurable)
- **Storage Service**: File and asset management
- **Tools System**: Lab management operations exposed as MCP tools

## Prerequisites

- **Python 3.12 or higher**
- **uv** package manager ([install from here](https://docs.astral.sh/uv/getting-started/installation/))
- **PostgreSQL** (for local development)
- **Container runtime**: Podman (recommended) or Docker
- **Git** for version control

For Red Hat environments:
- Access to Red Hat SSO (if using authentication)
- Red Hat certificate bundle (automatically configured in containers)

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd openshift-partner-labs-mcp-server

# Create and activate virtual environment
uv venv --python 3.12
source .venv/bin/activate

# Install the package in development mode
uv pip install -e ".[dev]"

# Install Red Hat certificates (if needed)
wget https://certs.corp.redhat.com/certs/Current-IT-Root-CAs.pem \
    && cat Current-IT-Root-CAs.pem >> `python -m certifi`
```

## Environment Configuration

Create a `.env` file in the project root:

```env
# MCP Server Configuration
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_TRANSPORT_PROTOCOL=http

# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=openshift_partner_labs
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password

# Authentication (optional)
ENABLE_AUTH=false
SSO_CLIENT_ID=your_client_id
SSO_CLIENT_SECRET=your_client_secret

# Logging
PYTHON_LOG_LEVEL=INFO
```

### Configuration Options

- **`ENABLE_AUTH`**: Set to `true` to enable OAuth2 authentication
- **`MCP_TRANSPORT_PROTOCOL`**: Choose from `http`, `streamable-http`, or `sse`
- **`POSTGRES_*`**: Database connection settings
- **`SSO_*`**: Red Hat SSO integration settings (required if `ENABLE_AUTH=true`)

## Security Considerations

⚠️ **IMPORTANT**: This server includes an OAuth2 compatibility mode (`COMPATIBLE_WITH_CURSOR`) that significantly reduces security to accommodate certain clients like Cursor.

### Transport Protocol Security

The server supports multiple transport protocols that can be configured via the `MCP_TRANSPORT_PROTOCOL` environment variable:

- **http/streamable-http**: Standard HTTP for request-response communication (both use the same implementation)
- **sse**: Server-Sent Events (SSE) for event-driven communication (deprecated)

**Note**: Both **http** and **streamable-http** protocols use the same HTTP implementation and are functionally identical. We recommend using **http** or **streamable-http** for most use cases as they provide the best compatibility and performance. The **SSE protocol** is deprecated and should only be used if specifically required for legacy clients.

## Usage

### Running Locally

1. **Start PostgreSQL** (if not already running):
   ```bash
   # Using the included PostgreSQL container
   podman-compose up -d postgres
   ```

2. **Start the MCP server**:
   ```bash
   # Method 1: Direct Python execution
   python -m openshift_partner_labs_mcp_server.src.main

   # Method 2: Using installed script (after pip install -e .)
   openshift-partner-labs-mcp-server

   # Method 3: Container development (recommended)
   make dev

   # Method 4: Direct container commands
   podman-compose up --build
   ```

3. **Verify the server is running**:
   ```bash
   curl http://localhost:8080/health
   ```

### Server Endpoints

Once running, the server provides these endpoints:

**HTTP Protocol** (default):
- **MCP Server**: `http://localhost:8080/mcp`
- **Health Check**: `http://localhost:8080/health`

**SSE Protocol** (if configured):
- **SSE Endpoint**: `http://localhost:8080/sse`
- **Health Check**: `http://localhost:8080/health`

## Available Tools

The server provides these MCP tools for OpenShift Partner Labs operations:

### Core Tools

- **`multiply_numbers`**: Mathematical operations and calculations
  - Performs multiplication of numeric values
  - Useful for capacity planning and resource calculations

- **`generate_code_review_prompt`**: Code analysis assistance
  - Generates structured code review prompts
  - Helps with quality assurance workflows

- **`get_redhat_logo`**: Red Hat branding assets
  - Retrieves Red Hat logo and branding materials
  - Supports documentation and UI development

### Usage Example

```python
# Using FastMCP client
from fastmcp import FastMCP
import asyncio

async def example():
    client = FastMCP("http://localhost:8080/mcp")
    result = await client.call_tool("multiply_numbers", {"a": 5, "b": 10})
    print(result)  # {"result": 50}

asyncio.run(example())
```

## OpenShift Deployment

The project includes complete OpenShift deployment configurations optimized for Red Hat environments.

### Quick Deployment

```bash
# Option 1: Use published container images (recommended)
# The openshift/ configurations automatically use the latest published images
oc apply -k openshift/

# Option 2: Deploy specific version
# Edit openshift/kustomization.yaml to specify image version
# images:
#   - name: openshift-partner-labs-mcp-server
#     newName: ghcr.io/mrhillsman/openshift-partner-labs-mcp-server
#     newTag: v0.2.0

# Check deployment status
oc get pods -n <your-namespace>

# View logs
oc logs -f deployment/openshift-partner-labs-mcp-server
```

### Production Endpoints

Once deployed on OpenShift, the server will be available at:

**HTTP Protocol**:
- **MCP Server**: `https://openshift-partner-labs-mcp-server.<your-cluster>/mcp`
- **Health Check**: `https://openshift-partner-labs-mcp-server.<your-cluster>/health`

**SSE Protocol**:
- **SSE Endpoint**: `https://openshift-partner-labs-mcp-server.<your-cluster>/sse`

### OpenShift Configuration

- **Port**: 8443 (HTTPS)
- **SSL**: Configured with TLS certificates
- **Resources**: 1 CPU, 1Gi memory
- **Health Checks**: Liveness and readiness probes configured
- **Image**: Red Hat UBI with Python 3.12

## Development & Testing

### Running Tests

```bash
# Using make targets (recommended)
make test                    # Run all tests
make test-cov               # Run tests with coverage (if available)

# Direct pytest commands
pytest                      # Run all tests
pytest --cov=openshift_partner_labs_mcp_server  # Run with coverage
pytest tests/test_tools.py  # Run specific test file
pytest -v                   # Verbose output
```

### Code Quality

Run these commands after making changes:

```bash
# Lint and auto-fix issues
ruff check --fix

# Format code
ruff format

# Type checking
mypy .

# Run all pre-commit hooks
pre-commit run --all-files
```

### Container Testing

```bash
# Test container build and execution
pytest tests/test_container.py -v

# Option 1: Use pre-built image from GitHub Container Registry
podman run -p 8080:8080 ghcr.io/mrhillsman/openshift-partner-labs-mcp-server:latest

# Option 2: Build container manually
podman build -t openshift-partner-labs-mcp-server .
podman run -p 8080:8080 openshift-partner-labs-mcp-server
```

## Releases

### Overview

This project uses automated GitHub Actions workflows for tag-based releases. When you push a version tag, the system automatically:

- **Validates quality**: Runs pre-commit hooks, tests, and type checking
- **Builds artifacts**: Creates Python packages and multi-platform container images
- **Creates releases**: Generates GitHub releases with changelogs and downloadable assets
- **Publishes images**: Pushes container images to GitHub Container Registry

### Creating a Release

Follow these steps to create a new release:

1. **Update the version** in `pyproject.toml`:
   ```bash
   # Edit pyproject.toml and update the version field
   vim pyproject.toml
   # Example: version = "0.2.0"
   ```

2. **Commit the version change**:
   ```bash
   git add pyproject.toml
   git commit -m "Bump version to 0.2.0"
   git push origin main
   ```

3. **Create and push the release tag**:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. **Monitor the release**: GitHub Actions will automatically:
   - Run quality checks and tests
   - Build Python packages and container images
   - Create a GitHub release with generated changelog
   - Publish artifacts for download

### Version Guidelines

- **Follow semantic versioning**: `major.minor.patch` (e.g., `1.2.3`)
- **Tag format**: Always prefix with `v` (e.g., `v0.2.0`)
- **Version consistency**: The version in `pyproject.toml` must exactly match the git tag
- **Pre-releases**: Versions < 1.0.0 are automatically marked as pre-release

### Release Artifacts

Each release produces:

**Python Packages**:
- Wheel distribution (`.whl`)
- Source distribution (`.tar.gz`)
- Available on GitHub Releases page

**Container Images**:
- Multi-platform images (linux/amd64, linux/arm64)
- Published to GitHub Container Registry
- Tagged with version and `latest`

**Installation Examples**:
```bash
# Install specific version
pip install openshift-partner-labs-mcp-server==0.2.0

# Use container image
podman run ghcr.io/mrhillsman/openshift-partner-labs-mcp-server:v0.2.0

# Use latest container image
podman run ghcr.io/mrhillsman/openshift-partner-labs-mcp-server:latest
```

### Release Validation

Before creating a release, ensure:
- All tests pass: `pytest`
- Code quality checks pass: `ruff check --fix && ruff format`
- Type checking passes: `mypy .`
- Pre-commit hooks pass: `pre-commit run --all-files`

The automated workflow will fail if any of these checks don't pass.

## Examples

### FastMCP Client

```bash
# Run the FastMCP client example
python examples/fastmcp_client.py
```

This example demonstrates:
- Connecting to the MCP server
- Using available tools (multiply_numbers, generate_code_review_prompt, get_redhat_logo)
- Mathematical operations and code analysis
- Asset retrieval functionality

### LangGraph Integration

```bash
# Run the LangGraph client example
python examples/langgraph_client.py
```

This example shows:
- LangGraph agent integration
- Google Gemini model usage
- Tool calls for mathematical operations
- Conversational AI workflows

## Contributing

We welcome contributions! Please follow these guidelines when contributing to the OpenShift Partner Labs MCP Server:

### Development Workflow

1. **Fork and clone** the repository
2. **Create a feature branch** from `main`
3. **Install development dependencies**: `uv pip install -e ".[dev]"`
4. **Make your changes** following the project's coding standards
5. **Run tests and quality checks**:
   ```bash
   pytest                    # Run all tests
   ruff check --fix          # Lint and auto-fix
   ruff format              # Format code
   mypy .                   # Type checking
   pre-commit run --all-files # Run all hooks
   ```
6. **Commit your changes** with clear, descriptive messages
7. **Submit a pull request** with a detailed description

### Code Standards

- **Python 3.12+** with type hints encouraged
- **Google docstring convention** for all functions
- **Ruff** for linting and formatting (enforced by pre-commit)
- **pytest** for testing with good coverage
- **Conventional commits** for clear change history

### Release Guidelines

For maintainers creating releases:

- **Version Updates**: Only update versions in `pyproject.toml` when preparing for release
- **Release Timing**: Create releases for significant feature additions, bug fixes, or security updates
- **Version Bumping**: Follow semantic versioning:
  - **Patch** (0.1.1): Bug fixes and minor improvements
  - **Minor** (0.2.0): New features that are backward compatible
  - **Major** (1.0.0): Breaking changes or major milestones
- **Pre-release Testing**: Ensure all automated checks pass before tagging
- **Release Notes**: The automated workflow generates changelogs, but consider adding manual release notes for major releases
- **Container Images**: All releases automatically publish multi-platform container images
- **Coordination**: For major releases, coordinate with the team and update documentation as needed

### Areas for Contribution

- **New MCP tools** for OpenShift Partner Labs operations
- **Database integrations** and data models
- **Authentication enhancements** and security improvements
- **Documentation** and usage examples
- **Testing** and quality assurance
- **Container and deployment** optimizations

For major changes, please open an issue first to discuss the proposed changes.

## License

This project is licensed under the Apache 2.0 License. See the `LICENSE` file for details.
