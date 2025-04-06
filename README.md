# simple auth

A simple application written to demonstrate benefits of contract first approach.

## why contract first

The **contract-first** approach is a method used in software development, particularly in the design of web services and
APIs. In this approach, the service contract (typically an interface definition, such as an OpenAPI specification, WSDL,
or JSON schema) is defined **before** the actual implementation of the service.

### Key Concepts:

- Contract as the Source of Truth: The API or service contract defines the structure, endpoints, data types, and
  communication rules.
- Implementation Follows the Contract: Developers write the backend code to match the specifications laid out in the
  contract.
- Consistency Across Teams: Frontend and backend teams can work in parallel since the contract is agreed upon in
  advance.
- Client-First Development: Consumers of the API (like mobile apps or other services) can begin development by mocking
  the
  service based on the contract.

### Benefits:

- Clear Communication: Ensures alignment between different teams by establishing a mutual understanding of how the
  service
  should behave.
- Reduced Errors: Catch inconsistencies early by validating the contract before writing code.
- Reusable Artifacts: The same contract can generate documentation, client SDKs, and even test cases.
- Scalability: Easier to maintain and expand services as the contract remains the guiding framework.

## why open-api

- [OpenAPI Initiative](https://www.openapis.org/)

The **OpenAPI Initiative (OAI)** is an open-source project under the **Linux Foundation** that focuses on standardizing
how APIs are described and documented. It governs the development of the **OpenAPI Specification (OAS)**, a widely
adopted format for describing RESTful APIs.

### What is the OpenAPI Specification (OAS)?

The OpenAPI Specification is a machine-readable document (usually in **YAML** or **JSON**) that outlines the structure,
endpoints, data types, authentication methods, and responses of an API. This allows developers to automate tasks such
as:

- Generating API documentation
- Creating server stubs and client SDKs
- Validating API requests and responses

#### Goals of the OpenAPI Initiative:

- **Interoperability**: Ensure consistency across API ecosystems, allowing APIs to work seamlessly together.
- **Automation**: Enable automated code generation, testing, and documentation.
- **Transparency**: Provide a clear contract for API consumers and developers.
- **Collaboration**: Facilitate communication between frontend, backend, and external stakeholders.

#### Key Benefits:

- **Standardization**: Promotes a unified format for describing APIs, making it easier to integrate with third-party
  services.
- **Reduced Development Time**: Tools like Swagger, Postman, and OpenAPI Generator streamline development using OpenAPI
  documents.
- **Enhanced Documentation**: API documentation is automatically generated, ensuring accuracy and reducing the manual
  workload.
- **Mocking and Testing**: Mock servers can simulate API responses based on the OpenAPI spec, allowing frontend and
  backend teams to work in parallel.

## requirements

- [Docker](https://docs.docker.com/get-docker/)

Docker runtime is enough to build everything. Every subproject contains build documentation.

## project structure

### state

- [db](./db/README.md)

### contract

- [open-api](./open-api/README.md) contract subproject

### client

- [simple-auth-react](./simple-auth-react/README.md)

### server

- [simple-auth-quarkus](./simple-auth-quarkus/README.md)
- [simple-auth-spring](./simple-auth-spring/README.md)

## run application

The application is run using multiple docker-compose.yaml files. Each type of backend service has its own separate
docker-compose.yaml file. All the prepared applications share the same endpoints:

- [traefik](http://localhost:8080)
- [MailDev](http://localhost:8081)
- Postgres SQL db instance, port: 5432, db: app, user: app, password: app
- [livez](http://localhost/api/livez)
- [readyz](http://localhost/api/readyz)
- [fe](http://localhost/)
- default user **simple@auth.org**/**simple**

**infra.yaml** - base infrastructure services reused by other docker compose yaml files.

### quarkus

start:

```shell
docker compose -f docker-compose-quarkus.yaml up
```

stop:

```shell
docker compose -f docker-compose-quarkus.yaml down
```

### spring

start:

```shell
docker compose -f docker-compose-spring.yaml up
```

stop:

```shell
docker compose -f docker-compose-spring.yaml down
```
