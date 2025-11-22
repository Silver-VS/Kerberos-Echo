# Introduction

This project is a didactic implementation of a Kerberos-style authentication
system in Java, designed to illustrate how a zero-trust network can be
secured using symmetric keys, tickets and a small set of roles:

- **Client**
- **Authentication Server (AS)**
- **Ticket Granting Server (TGS)**
- **Application Server (Server)**

The code is intentionally minimal and explicit. It favors readability and
step‑by‑step tracing of the protocol over optimizations or production-ready
patterns.

The implementation can run:

- Entirely on a **single VM** (all roles as separate JVM processes on
  `localhost`), or
- In a **multi-node setup** across an insecure LAN, where each role runs on
  a different host.

---

## 1. Audience and learning goals

This project is aimed at:

- Students learning about network security and authentication protocols.
- Engineers who want a concrete, readable example of Kerberos-style
  ticket exchanges without the complexity of a full Kerberos implementation.
- Anyone exploring the idea of zero-trust architectures in a small,
  self-contained codebase.

After working with this project, you should be able to:

1. Explain the roles of Client, AS, TGS and Server in Kerberos.
2. Follow the three main protocol steps:
   - AS-REQ / AS-REP
   - TGS-REQ / TGS-REP
   - AP-REQ / AP-REP
3. Understand how symmetric keys and tickets are used to avoid sending
   passwords over the network.
4. See how a zero-trust mindset is applied: nobody is trusted by default;
   every access requires a ticket and a valid session key.
5. Navigate the code and map each step to specific classes and methods.

---

## 2. Zero trust and Kerberos (conceptual)

### 2.1 Zero-trust in a nutshell

A zero-trust network assumes:

- The network is **inherently insecure**.
- No node is trusted just because it is “inside the perimeter”.
- Every request must be authenticated and, ideally, authorized.
- Identities and permissions should be short-lived and verifiable.

In practice, this means:

- Machines/services never blindly trust incoming connections.
- Clients prove who they are via cryptographic credentials (keys, tokens,
  tickets).
- Access is granted based on fresh, verifiable data, not static assumptions.

### 2.2 Where Kerberos fits

Kerberos is a classic protocol used to implement single sign-on and
mutual authentication in such environments. Instead of passwords flying
around the network, Kerberos uses:

- A central Authentication Server (AS).
- A Ticket Granting Server (TGS).
- Tickets encrypted with keys only specific parties know.
- Session keys used for short-lived secure communication.

Very roughly:

1. The Client proves its identity to the **AS**, and receives a
   **Ticket-Granting Ticket (TGT)** plus a session key `K_c,tgs`.
2. The Client uses the TGT to ask the **TGS** for access to a specific
   service. The TGS responds with:
   - A **service ticket** (for the Server).
   - A session key `K_c,s` (for Client ↔ Server).
3. The Client uses the service ticket and `K_c,s` to prove its identity to
   the **Server**, which verifies the ticket and establishes a secure
   session.

Throughout this process, passwords never need to cross the network.
Instead, keys and tickets do.

This project follows the same shape as Kerberos, but with deliberate
simplifications to keep the implementation small and clear.

---

## 3. What this project implements

### 3.1 Roles and packages

The Java code is organized into four main roles under
`java/Controllers/Kerberos`:

- `Controllers.Kerberos.AS`
  - `Controller` – network entry point for the Authentication Server.
  - `ProcessRequest` – handles AS-REQ, issues TGT and `K_c,tgs`.

- `Controllers.Kerberos.TGS`
  - `Controller` – network entry point for the Ticket Granting Server.
  - `ProcessRequest` – handles TGS-REQ, issues service tickets and `K_c,s`.

- `Controllers.Kerberos.Server`
  - `Controller` – network entry point for the protected service.
  - `ProcessRequest` – handles AP-REQ, validates tickets, returns AP-REP.

- `Controllers.Kerberos.Client`
  - `Controller` – orchestrates the full client-side flow
    (AS-REQ → TGS-REQ → AP-REQ).
  - `RequestAccess` – builds and sends the different protocol messages.

Supporting layers:

- `java/Model`
  - `Ticket`, `UTicket` – protocol payloads (tickets and bundles of tickets).
  - `Messenger` – thin networking and serialization helper.
  - `TimeMethods` – timestamp and lifetime utilities.
  - `KeyDistributor`, `KeyObject` – support for key exchange.

- `java/Security/Model`
  - `Encryption` – RSA and symmetric (DES) encryption helpers.
  - `KeyMethods` – key generation, serialization and recovery.

- `java/Security/SecretVault`
  - `Generated/` – each principal’s own RSA key pair.
  - `Connection/` – **long-term symmetric keys** and **received public keys**.

### 3.2 Two main phases

1. **Distributor phase (crypto bootstrap)**

   Under `Controllers.Distributor.*`, the system:

   - Generates RSA key pairs for each principal via `KeyCreation`.
   - Exchanges public keys and establishes symmetric keys between pairs
     using `Sender` and `Receiver` plus `Model.KeyDistributor`.

   This phase simulates the **initial provisioning** of trust relationships.

2. **Kerberos phase (authentication protocol)**

   Under `Controllers.Kerberos.*`, the system:

   - Runs AS, TGS and Server as simple TCP services with one `ServerSocket`
     each.
   - Runs the Client, which:
     - Talks to AS (AS-REQ / AS-REP).
     - Talks to TGS (TGS-REQ / TGS-REP).
     - Talks to Server (AP-REQ / AP-REP).
   - Uses tickets (`Ticket`, `UTicket`) and symmetric keys stored in
     `SecretVault/Connection` to secure communications.

---

## 4. What is intentionally simplified

This project is **not** a full Kerberos implementation. It intentionally
simplifies several aspects to stay focused on the protocol’s core ideas:

- **No passwords / KDC database**
  - Real Kerberos derives client keys from user passwords and a KDC
    database.
  - Here, long-term keys are pre-distributed by the **Distributor** phase
    and saved in files.

- **Crypto choices**
  - Uses RSA for public-key operations and DES for symmetric encryption.
  - Uses JCE defaults instead of explicitly configuring modes (CBC/GCM, IVs).
  - Suitable for educational use, not for production security.

- **Single realm, single TGS, single service**
  - No cross-realm trust.
  - Only one TGS and one demo server are implemented.

- **Limited replay protection**
  - Tickets and authenticators carry timestamps and lifetimes.
  - There is **no replay cache** storing previously seen authenticators.
  - Replay protection is best-effort and mainly illustrative.

- **Client visibility of tickets**
  - In real Kerberos, some tickets remain opaque to the client.
  - Here, for learning purposes, the client can decrypt and print most
    tickets to the console, so you can see exactly what they contain.

- **Hardcoded configuration**
  - Hosts, ports and filesystem paths are hardcoded at the top of the
    controllers.
  - This keeps the demo easy to follow at the cost of flexibility.

Despite these simplifications, the **protocol structure** closely mirrors
Kerberos and is suitable for demonstrations of zero-trust ideas.

---

## 5. How to explore the project

Recommended reading order for the docs:

1. **This introduction** – you are here.
2. **[`docs/architecture.md`](architecture.md)**
   - High-level view of how the codebase is structured:
     - Controllers, Model, Security.
     - Relationship between Distributor and Kerberos phases.

3. **[`docs/SecretVault.md`](SecretVault.md)**
   - How keys are stored on disk.
   - Difference between `Generated/` and `Connection/`.
   - Naming conventions for `.key` files and what they represent.

4. **[`docs/protocol.md`](protocol.md)**
   - Detailed mapping of each Kerberos step (AS-REQ, TGS-REQ, AP-REQ) to:
     - Specific classes (`ProcessRequest` and `RequestAccess`).
     - Concrete ticket fields and crypto operations.

5. **[`docs/running.md`](running.md)**
   - Step-by-step instructions to:
     - Generate keys.
     - Start all services.
     - Run the client.
     - Optionally distribute roles across multiple machines.

As you read, you can keep your IDE open on:

- `Controllers.Kerberos.Client.Controller` – full client-side flow.
- `Controllers.Kerberos.AS/TGS/Server.ProcessRequest` – server-side logic.
- `Model.UTicket` – how tickets are built, encrypted and decrypted.
- `Security.Model.KeyMethods` – how keys are created and stored.

Together, these files give you a concrete, inspectable example of how a
Kerberos-style protocol can be implemented in Java and used to secure a
zero‑trust network environment.

---

## 6. Suggested demo storyline

When presenting this project, you can structure the demo around the following
story:

1. **“Assume the network is hostile”**
   - No node trusts any other by default.
   - All we have are cryptographic keys.

2. **Show the key bootstrap (Distributor)**
   - RSA keys in `SecretVault/Generated`.
   - Symmetric keys in `SecretVault/Connection`.

3. **Run the Kerberos flow**
   - Start AS, TGS and Server.
   - Run the Client.
   - Watch the console logs for:
     - AS issuing a TGT and `K_c,tgs`.
     - TGS issuing a service ticket and `K_c,s`.
     - Server validating the ticket and returning AP-REP.

4. **Connect it back to zero-trust**
   - The Server never trusts the Client “because it’s on the LAN”.
   - It only trusts what it can verify: a valid encrypted ticket from TGS
     plus a correct authenticator using `K_c,s`.

This narrative makes it clear how the pieces you see in the code relate to
real-world secure systems and modern zero-trust thinking.