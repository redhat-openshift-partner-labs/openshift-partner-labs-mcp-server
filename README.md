# README IS WIP

# OpenShift Partner Labs MCP Server
MCP Server to work with OpenShift Partner Labs. This MCP server is designed to only work with OpenShift Partner Labs providing read/write operations normally performed by lab managers, administrators, and developers.

![Project Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

## Purpose and Philosophy

This server is **not** a traditional REST API that provides a one-to-one mapping of database interactions. Instead, its core philosophy is to **aggregate low-level interactions into high-level, conversational actions** that can be easily used by an AI agent.

The primary goal is to address the challenges of traditional UIs, such as:

* **High development overhead:** Reducing the developer "cycles" needed for UI changes.
* **Developer dependency:** Empowering users to perform routine operational tasks (like changing a cluster's state) via the agent without needing a developer.
* **Complex workflows:** Simplifying processes like cluster provisioning into guided, natural language conversations.

Developers contributing to this server should always consider if they are providing a tool, prompt, or resource that empowers the agent to fulfill a high-level user request, rather than simply exposing a raw backend function.

## High-Level Architecture

This server functions as the critical **API Layer** in our new AI-driven architecture, sitting between the agent and the backend database.

`[User] <--> [Chat Interface] <--> [AI Agent] <--> [MCP Server] <--> [MySQL Database]`

## Prerequisites

Before you begin, ensure you have the following installed:

* Go (version 1.18 or newer)
* Access to a running MySQL instance
* Git

## Getting Started

To get the server running on your local machine, follow these steps:

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/redhat-openshift-partner-labs/openshift-partner-labs-mcp-server.git](https://github.com/redhat-openshift-partner-labs/openshift-partner-labs-mcp-server.git)
    cd openshift-partner-labs-mcp-server
    ```

2.  **Install dependencies:**
    ```sh
    go mod tidy
    ```

3.  **Configure your environment:**
    Create a `.env` file in the root of the project by copying the example file.
    ```sh
    cp .env.example .env
    ```
    Now, edit the `.env` file with your local configuration, such as database credentials.

4.  **Run the server:**
    ```sh
    go run ./cmd/server/main.go
    ```
    The server should now be running locally and ready to accept requests.

## Contributing

We welcome contributions! If you're interested in helping improve the MCP Server, please read our `CONTRIBUTING.md` file to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes.

## License

This project is licensed under the Apache 2.0 License. See the `LICENSE` file for details.
