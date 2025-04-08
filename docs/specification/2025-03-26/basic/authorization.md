---
title: Authorization
type: docs
weight: 15
---

{{< callout type="info" >}} **Protocol Revision**: TBD {{< /callout >}}

## 1. Introduction

### 1.1 Purpose and Scope

The Model Context Protocol provides authorization capabilities at the transport level, enabling MCP
clients to make requests to restricted MCP servers on behalf of resource owners. This specification
defines the authorization flow for HTTP-based transports.

The scope of this document is **user authorization** - how a client can authenticate a user to access a
server and the server determine whether to authorize the user to access its tools, resources, or any
other capabilities.

This document **does not discuss server-to-server authorization patterns**.

### 1.2 Baseline tenets

1. **MCP server developers are not security experts**. The current specification assumes that developers
   will be building their own authorization server. That is not something they ever need to do in the
   context of MCP servers. This also introduces room for serious mistakes that can lead to compromise.
1. **MCP clients are identity provider (IdP)-agnostic**. We do not and will not expect clients to be
   "enlightened" in any capacity to support a protected MCP server. This will fragment the ecosystem.
   The specification explicitly assumes that clients are not enabled in any unique way to support
   specific IdPs.
    - **Note:** It is acceptable for clients to be enhanced for specific IdPs, primarily through
      pre-registration.
1. **MCP clients perform user authentication without the server.** The MCP server can guide the client
   to the IdP but will not be responsible for authenticating the user and obtaining credential
   artifacts for the user. The server might transform incoming credential artifacts, like tokens, but
   it does not do any kind of exchange for the user in the client, nor does the MCP server have access
   to any user authentication credentials or protocols.
1. **We focus on OAuth 2.1, with room for extensibility for other providers/specifications.** Our
   running assumption is that most developers will want to use OAuth 2.1, however in the long-run
   unusual cases for authentication and authorization may emerge (e.g., mTLS, Kerberos), which will
   need clients to be extensible.

### 1.3 Protocol Requirements

Authorization is **OPTIONAL** for MCP implementations. When supported:

- Streamable HTTP or SSE transports **SHOULD** conform to this specification.
- Implementations using an STDIO transport **SHOULD NOT** follow this specification and instead
  retrieve credentials from the environment.
- Implementations using alternative transports **MUST** follow established security best practices for
  their protocol.

### 1.4 Standards Compliance

This authorization mechanism is based on established specifications listed below, but implements a
selected subset of their features to ensure security and interoperability while maintaining simplicity:

- [OAuth 2.1 IETF DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12)  
- OAuth 2.0 Authorization Server Metadata
  ([RFC8414](https://datatracker.ietf.org/doc/html/rfc8414))  
- OAuth 2.0 Dynamic Client Registration Protocol
  ([RFC7591](https://datatracker.ietf.org/doc/html/rfc7591))  
- OAuth 2.0 Demonstrating Proof of Possession (DPoP)
  ([RFC9449](https://datatracker.ietf.org/doc/html/rfc9449))  
- Resource Indicators for OAuth 2.0
  ([RFC8707](https://www.rfc-editor.org/rfc/rfc8707.html))

This specification **DOES NOT** require MCP server developers to implement their own OAuth Provider
(OP) and instead relies on developers adopting dedicated and well-tested third-party Identity
Providers (IdPs).

This specification also enables existing deployments to leverage their current infrastructure.
As a side-effect, this also simplifies consent flows, and services that have multiple MCP Servers
won't require individual registration per client:server pair.

## 2. Authorization Flow

### 2.1 Overview

1. Identity providers **MUST** implement OAuth 2.1 with appropriate security measures for both
   confidential and public clients.

2. Identity providers **SHOULD** support the OAuth 2.1 Dynamic Client Registration Protocol
   ([RFC7591](https://datatracker.ietf.org/doc/html/rfc7591)).

3. Identity providers **SHOULD** implement and MCP clients **MUST** consume OAuth 2.0 Authorization
   Server Metadata ([RFC8414](https://datatracker.ietf.org/doc/html/rfc8414)). Servers that do not
   support Authorization Server Metadata **MUST** follow the default URI schema.

### 2.2 Client OAuth 2.1 Authorization

When authorization is required and not yet proven by the client, servers **MUST** respond with
*HTTP 401 Unauthorized*.

A *HTTP 401 Unauthorized* response **MUST** include a `WWW-Authenticate` header with information about
the issuer that the server is using to authenticate in the following format:

`WWW-Authenticate: Bearer realm="default", issuer="https://idp.example",`  
`scope="mcp_access_tool1", resource="https://mcp-server.example"`  
`WWW-Authenticate: DPoP realm="default", issuer="https://idp.example",`  
`scope="mcp_access_tool1", resource="https://mcp-server.example",`  
`algs="ES256 PS256"`

An MCP client **SHOULD** evaluate or permit the user to evaluate the trustworthiness of issuers
discovered this way (to prevent phishing). For example, an MCP client could prompt the user "Do you
want to login with `https://idp.example`?"

An MCP client **MUST** use the `issuer` identifier to construct the OAuth 2.0 metadata discovery
document path, following
[RFC8414](https://datatracker.ietf.org/doc/html/rfc8414#section-3).

An MCP client **MAY** use the `registration_endpoint` to register itself with OAuth Provider. An MCP
client **MAY** also be pre-registered with certain OAuth Providers.

An MCP client **MUST** check the `resource` identifier against the hostname of the MCP server. An MCP
client **MUST** send the `resource` identifier to the OAuth Provider, following
[RFC8707](https://www.rfc-editor.org/rfc/rfc8707.html).

An MCP client **SHOULD** implement Demonstrating Proof of Possession (DPoP) and use it to the extent
supported by the OAuth Provider. See
[RFC9449](https://datatracker.ietf.org/doc/html/rfc9449).

Clients initiate an
[OAuth 2.1 (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12) authorization
flow after receiving the *HTTP 401 Unauthorized*.

The following demonstrates the OAuth 2.1 flow for public clients using PKCE for a pre-registered public client.

```mermaid
sequenceDiagram
    participant UA as User-Agent (Browser or App/Broker)
    participant MC as MCP Client
    participant MS as MCP Server
    participant IDP as Identity Provider

    MC->>MS: MCP Request
    MS-->>MC: 401 Unauthorized with issuer, scope, and resource in WWW-Authenticate
    MC->>MC: Construct OIDC /authorize endpoint from issuer identifier
    Note over MC: Generate code_verifier and code_challenge,<br/>and request with scope and resource
    MC-->>UA: Open /authorize
    UA-->>IDP: User authenticates
    UA->>MC: Return auth code to client
    MC->>IDP: Exchange auth code for tokens
    IDP-->>MC: Return tokens
    MC->>MC: Store tokens securely
    Note over MC, MS: Begin standard MCP message exchange
```

### 2.3 Server Metadata Discovery

Servers **MUST** return the issuer identifier in `WWW-Authenticate` headers in a
*HTTP 401 Unauthorized* response.

For servers that are overriding identity provider capabilities, such as those for token exchange or
dynamic client registration, they **MUST** return their fully-qualified domain as the issuer in
`WWW-Authenticate` headers in a *HTTP 401 Unauthorized* response.

For server capability discovery:

- MCP clients **MUST** parse the `WWW-Authenticate` response to discover the issuer URL, and construct
  the metadata endpoint from that issuer identifier.  
- MCP servers **SHOULD** use a third-party identity provider and include its issuer in
  *HTTP 401 Unauthorized* responses.  
- MCP clients **SHOULD** evaluate or enable the user to evaluate the trustworthiness of identity
  providers.  
- Identity providers **MUST** support
  [OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- MCP servers **MUST** respond to an unauthorized request with a `WWW-Authenticate` header containing
  `issuer`, `scope`, and `resource` identifiers.

The discovery flow is illustrated below:  

```mermaid
sequenceDiagram
    participant MC as MCP Client
    participant MS as MCP Server
    participant IDP as Identity Provider

    MC->>MS: Request data
    MS-->>MC: 401 Unauthorized with WWW-Authenticate
    MC->>MC: Construct metadata endpoint from issuer identifier

    Note over MC: Continue with authorization flow
```

#### 2.3.1 Server Metadata Discovery Headers

MCP clients **SHOULD** include the header `MCP-Protocol-Version: <protocol-version>` during Server
Metadata Discovery to allow the MCP server to respond based on the MCP protocol version.

For example: `MCP-Protocol-Version: 2024-11-05`

### 2.4 Identity provider integration

#### 2.4.1 Overview

MCP servers **MAY** override endpoints on an as-needed basis if the identity provider requires
additional gestures that are not captured by the specification.

MCP servers **MUST NOT** complete PKCE or other public client flows on behalf of the client.

MCP servers that do not implement a [metadata discovery process](#23-server-metadata-discovery) must
be assumed to implement the OAuth flow through standard endpoints (e.g., `/authorize` and `/token`)

#### 2.4.2 Flow Description

The third-party authorization flow comprises these steps:

1. MCP client requests data from the MCP server.  
1. MCP server responds with *HTTP 401 Unauthorized* and `WWW-Authenticate` header containing the
   `issuer`, `scope`, and `resource`.  
1. MCP client retrieves the `/authorize` endpoint from the `issuer` metadata document.  
1. MCP client redirects user to identity provider's `/authorize` endpoint. MCP client uses `scope` and
   `resource` parameters provided in the `WWW-Authenticate` header in the `/authorize` URL.  
1. User authorizes with identity provider with `scope` and `resource`.  
1. Identity provider redirects back to MCP client with authorization code.  
1. MCP client exchanges the code for the requested tokens.  
1. MCP client caches the token.  
1. MCP clients can now request data from the MCP server with the token attached in the `Authorization`
   header.

```mermaid
sequenceDiagram
    participant UA as User-Agent (Browser)
    participant MC as MCP Client
    participant MS as MCP Server
    participant IDP as Third-Party Auth Server

    MC->>MS: Request data
    MS-->>MC: 401 Unauthorized with WWW-Authenticate
    Note over MC: MCP Client retrieves /authorize endpoint URI from the issuer metadata document (Section 2.3)
    MC-->>UA: Initiate authorization request at /authorize
    Note over UA: User authenticates and authorizes client for scope and resource
    UA->>MC: Return auth code to client
    MC->>IDP: Exchange code for token
    IDP-->>MC: Third-party access token
    MC->>MC: Cache token
```

#### 2.4.3 Session Binding Requirements

MCP servers integrating with third-party authorization services **MUST**:

1. Maintain secure mapping between third-party tokens and issued client sessions.  
2. Validate third-party token status before honoring MCP tokens.  
3. Implement appropriate token lifecycle management.  
4. Provide appropriate responses to the client if re-authentication is needed. Please refer to
   [RFC 9470 OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470.html).

#### 2.4.4 Security Considerations

When implementing authorization with identity providers, MCP servers **MUST**:

1. Request the minimum number of required scopes.  
2. Securely store any credential artifacts obtained from the client and/or the IdP.  
3. Implement appropriate session timeout handling.  
4. Consider security implications of token chaining.  
5. Implement proper error handling for third-party auth failures.

MCP clients **MUST**:

1. Securely store authentication tokens received from the identity provider.  
2. Properly handle request to re-authenticate users with expired or invalid tokens.  
3. Verify that the resource identifier returned matches the FQDN of the MCP server.  
4. Forward the resource identifier returns as `resource` parameter according to
   [RFC8707](https://www.rfc-editor.org/rfc/rfc8707.html).

Identity providers **MUST**:

1. Verify that the resource identifier is registered for the audience of the access token issued.

### 2.5 Implementing server overrides

In certain scenarios, identity providers might have limited capability support and MCP server
developers may choose to supplement those with their own implementation. In this scenario, the server
**MUST** return its fully-qualified domain name as the `issuer` in the *HTTP 401 Unauthorized*
response, included in the `WWW-Authenticate` header.

#### 2.5.1 Discovery of server-driven overrides

Under all circumstances, the server **MUST** return a `WWW-Authenticate` with `issuer` information,
even if the server provides its own metadata document that overrides IdP endpoints (such as
`/authorize`, `/token`, or `/register`).

#### 2.5.2 Fallbacks for Servers without Metadata Discovery

For servers that do not implement OAuth 2.0 Authorization Server Metadata, clients **MUST** use the
following default endpoint paths relative to the authorization base URL (as defined in
[Section 2.5.1](#251-discovery-of-server-driven-overrides):

| Endpoint               | Default Path   | Description                          |
| ---------------------- | -------------- | ------------------------------------ |
| Authorization Endpoint | `/authorize`   | Used for authorization requests      |
| Token Endpoint         | `/token`       | Used for token exchange & refresh    |
| Registration Endpoint  | `/register`    | Used for dynamic client registration |

For example, with an MCP server hosted at `https://api.example.com/v1/mcp`, the default endpoints
would be:

- `https://api.example.com/authorize`  
- `https://api.example.com/token`  
- `https://api.example.com/register`

Clients **MUST** first attempt to discover endpoints via the metadata document before falling back to
default paths. When using default paths, all other protocol requirements remain unchanged.

### 2.6 Dynamic Client Registration

MCP clients **SHOULD** support the
[OAuth 2.0 Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591) to
allow MCP clients to obtain OAuth client IDs without user interaction. This provides a standardized
way for clients to automatically register with new servers, which is crucial for MCP because:

- Clients cannot know all possible servers in advance  
- Manual registration would create friction for users  
- It enables seamless connection to new servers  
- Servers can implement their own registration policies

MCP clients that want to dynamically register OAuth clients with the target identity provider **MUST**
provide the `software_id` and `software_version` parameters, as defined in the
[Client Metadata](https://datatracker.ietf.org/doc/html/rfc7591#section-2) section of
[RFC7591](https://datatracker.ietf.org/doc/html/rfc7591).

MCP clients with mass audiences will *generally* want to pre-register and hardcode client IDs. Some
OAuth Providers (such as Google and Microsoft) limit the functionality of dynamically registered
clients. An MCP client could contain a config for common issuers like:

```json
[
  { "issuer":"https://idp.example", "client_id":"12345"},
  { "issuer":"https://idp2.example", "client_id":"urn:client_ids:546"}
]
```

Alternatively, an MCP client could allow the user to register the MCP client and provide those details
to the MCP client through a UI.

### 2.7 Authorization Flow Steps

The complete authorization flow proceeds as follows:  

```mermaid
sequenceDiagram
    participant UA as User-Agent (Browser or App/Broker)
    participant MC as MCP Client
    participant MS as MCP Server
    participant IDP as Identity Provider

    MC->>MS: Request data
    MS-->>MC: 401 Unauthorized with WWW-Authenticate
    MC->>MC: Construct metadata document path

    alt Supports identity provider
        MC->>IDP: GET /.well-known/oauth-authorization-server
        IDP-->>MC: Return endpoint metadata
    else Partial or No IDP Support
        MC->>MS: GET /.well-known/oauth-authorization-server
        alt Discovery Success
            MS-->>MC: 200 OK + Metadata Document
            Note over MC: Use endpoints from metadata
        else Discovery Failed
            MS-->>MC: 404 Not Found
            Note over MC: Fall back to default endpoints
        end
    end

    alt Client is pre-registered for the identity provider
    else Identity provider supports dynamic client registration
        MC->>IDP: Request client registration
        IDP-->>MC: Confirm client registration
    else Identity provider does not support dynamic client registration
        MC->>MS: Request client registration
        MS->>IDP: Register client
        IDP-->>MS: Return client registration
        MS-->>MC: Return client registration
    end

    Note over MC: Generate PKCE artifacts
    MC-->>UA: Initiate authorization call
    Note over UA: User authenticates and authorizes client for scope and resource
    UA->>MC: Return auth code to client
    MC->>IDP: Exchange auth code for tokens
    IDP-->>MC: Return tokens
    MC->>MC: Cache tokens
    Note over MC, MS: Begin standard MCP message exchange
```

#### 2.7.1 Decision Flow Overview

```mermaid
flowchart TD
    A[Start Authorization Flow] --> AA[Get authority]
    AA-->B{Check Metadata Discovery}
    B -->|Available| C[Use Metadata Endpoints]
    B -->|Not Available| D[Use Default Endpoints]

    C --> G{Check Registration Endpoint}
    D --> G

    G -->|Available| H[Perform Dynamic Registration]
    G -->|Not Available| I[Alternative Registration Required]

    H --> J[Start OAuth Flow]
    I --> J

    J --> K[Generate PKCE Parameters]
    K --> L[Request Authorization]
    L --> M[User Authorization]
    M --> N[Exchange Code for Tokens]
    N --> O[Use Access Token]
```

### 2.8 Access Token Usage

#### 2.8.1 Token Requirements

Access token handling **MUST** conform to
[OAuth 2.1 Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-5) or
[DPoP Section 7](https://datatracker.ietf.org/doc/html/rfc9449#section-7) requirements for resource
requests. Specifically:

MCP client **MUST** use the Authorization request header field
[OAuth Section 5.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-5.1.1):

```http
Authorization: Bearer <access-token>
```

or
[DPoP Section 7.1](https://datatracker.ietf.org/doc/html/rfc9449#name-the-dpop-authentication-sch):

```http
Authorization: DPoP <access-token>
DPoP: <DPoP proof>
```

Note that authorization **MUST** be included in every HTTP request from client to server, even if they
are part of the same logical session.

Access tokens **MUST NOT** be included in the URI query string. Example request:

```http
GET /v1/contexts HTTP/1.1
Host: mcp.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

#### 2.8.2 Token Handling

Resource servers (MCP servers _or_ downstream APIs) **MUST** validate access tokens as described
in [Section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-5.2).

If validation fails, servers **MUST** respond according to
[Section 5.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-5.3) error
handling requirements. Invalid or expired tokens **MUST** receive a `HTTP 401` response.

### 2.9 Security Considerations

The following security requirements **MUST** be implemented:

1. Clients **MUST** securely store tokens following OAuth 2.1 best practices.  
1. Servers **MUST** validate all incoming tokens.
1. All authorization endpoints **MUST** be served over HTTPS.  
1. Servers **MUST** validate redirect URIs to prevent open redirect vulnerabilities.  
1. Redirect URIs **MUST** be either `localhost` URLs or HTTPS URLs.  
1. Special considerations **MUST** be accounted for to prevent phishing through MCP servers.

### 2.10 Error Handling

Servers **MUST** return appropriate HTTP status codes for authorization errors:

| Status Code | Description  | Usage                                      |
| ----------- | ------------ | ------------------------------------------ |
| 401         | Unauthorized | Authorization required or token invalid    |
| 403         | Forbidden    | Invalid scopes or insufficient permissions |
| 400         | Bad Request  | Malformed authorization request            |

### 2.11 Implementation Requirements

1. Implementations **MUST** follow OAuth 2.1 security best practices.  
2. PKCE is **REQUIRED** for all clients.  
3. Token rotation **SHOULD** be implemented for enhanced security.  
4. Token lifetimes **SHOULD** be limited based on security requirements.

## 3. Best Practices

### 3.1 Local clients as Public OAuth 2.1 Clients

We strongly recommend that local clients implement OAuth 2.1 as a public client:

1. Utilizing code challenges (PKCE) for authorization requests to prevent interception attacks.  
2. Implementing secure token storage appropriate for the local system.  
3. Following token refresh best practices to maintain sessions.  
4. Properly handling token expiration and renewal.

### 3.2 Authorization Metadata Discovery

We strongly recommend that all clients implement metadata discovery. This reduces the need for users
to provide endpoints manually or clients to fallback to the defined defaults.

### 3.3 Dynamic Client Registration

Since clients do not know the set of MCP servers in advance, we strongly recommend the implementation
of dynamic client registration. This allows applications to automatically register with the MCP
server, and removes the need for users to obtain client IDs manually.

### 3.4 Using delegated authorization

MCP servers **SHOULD** support delegated authorization through third-party authorization servers
instead of implementing their own OAuth provider. MCP server **MAY** act as the proxy for
the identity provider.
