# Architecture Overview

This document describes the overall architecture of the Kerberos demo project:
the main components, their responsibilities, and how they interact.

The project implements a simplified Kerberos-style authentication flow with
four roles:

- **Client**
- **Authentication Server (AS)**
- **Ticket Granting Server (TGS)**
- **Application Server (Server)**

Each role is implemented as an independent Java process, communicating over
TCP sockets, and using a filesystem-based keystore (`SecretVault`) for keys.

---

## 1. High-level structure

Relevant source layout:

```text
src/main/java
├── Controllers
│   ├── Distributor
│   │   ├── AS
│   │   │   ├── KeyCreation.java
│   │   │   └── Receiver.java
│   │   ├── Client
│   │   │   ├── KeyCreation.java
│   │   │   └── Sender.java
│   │   ├── Server
│   │   │   ├── KeyCreation.java
│   │   │   └── Sender.java
│   │   └── TGS
│   │       ├── KeyCreation.java
│   │       ├── Receiver.java
│   │       └── Sender.java
│   └── Kerberos
│       ├── AS
│       │   ├── Controller.java
│       │   └── ProcessRequest.java
│       ├── Client
│       │   ├── Controller.java
│       │   └── RequestAccess.java
│       ├── Server
│       │   ├── Controller.java
│       │   └── ProcessRequest.java
│       └── TGS
│           ├── Controller.java
│           └── ProcessRequest.java
├── Model
│   ├── KeyDistributor.java
│   ├── KeyObject.java
│   ├── Messenger.java
│   ├── Ticket.java
│   ├── TimeMethods.java
│   └── UTicket.java
└── Security
    ├── Model
    │   ├── Encryption.java
    │   └── KeyMethods.java
    └── SecretVault
        ├── Generated/
        └── Connection/
```

At a high level, there are four layers:

1. Controllers – entry points and protocol logic (Distributor + Kerberos).
2. Model – core protocol objects and network helpers.
3. Security.Model – cryptographic primitives and key management.
4. Security.SecretVault – filesystem-backed keystore for all keys.

This architecture is deliberately modular: you can inspect and reason about each part (networking, tickets, keys, roles)
in isolation, while still seeing the complete Kerberos-style flow when you run the project.

---

## 2. Controllers

### 2.1 Distributor controllers (key bootstrap phase)

The Distributor package handles the initial, out-of-band key distribution
between roles. It is split per role:

- `Controllers.Distributor.AS.*`
- `Controllers.Distributor.Client.*`
- `Controllers.Distributor.Server.*`
- `Controllers.Distributor.TGS.*`

Each role contains:

* `KeyCreation.java`

  Generates an RSA key pair (public/private) for that role using
  `Security.Model.KeyMethods.keyCreator(...)` and stores it under
  `Security/SecretVault/Generated/`.

- `Sender.java` and/or `Receiver.java`

  Use `Model.KeyDistributor` and `Model.Messenger` to:
    * Exchange public keys.
    * Establish a shared symmetric DES key.
    * Store symmetric keys under `Security/SecretVault/Connection/` with the
      naming convention `Symmetric-<Owner>-<WithWho>.key`.

**Execution pattern:**

For any pair of roles that need a long-term symmetric key:

1. Start the appropriate `Receiver` main first (listening `ServerSocket`).

2. Then start the matching `Sender` main (client `Socket`).

If the Sender starts before the Receiver is listening, the connection will
simply fail (plain `Socket/ServerSocket`, no retry logic).

The Distributor phase prepares all RSA and symmetric keys needed by the
Kerberos phase.

---

### 2.2 Kerberos controllers (protocol phase)

The Kerberos package contains the runtime services for each role.

#### 2.2.1 Authentication Server (AS)

1. `Controllers.Kerberos.AS.Controller`

    * Configures:

        - A listening port (e.g. `1121`).

        - projectPath and derived paths to:

            - `SecretVault/Generated/` (AS’s own keys).

            - `SecretVault/Connection/` (shared symmetric keys).

    - Initializes a `ServerSocket` via `Model.Messenger.serverSocketInitializer(...)`.

    - Enters a loop:

        - Accepts incoming sockets (`Messenger.requestAccepter`).

        - Delegates to `AS.ProcessRequest.processUserRequest(...)`.

        - Logs success/failure.

2. `Controllers.Kerberos.AS.ProcessRequest`

   Implements AS-REQ → AS-REP logic:

    - Reads a `UTicket` from the socket via `Messenger.ticketAccepter`.

    - Extracts the `request` ticket (client ID, requested service, lifetime).

    - Generates a session key `K_c`,`tgs` for Client–TGS.

    - Constructs:

        - `responseToClient` ticket (visible to the client).

        - `TGT` ticket (Ticket-Granting Ticket, for the TGS).

    - Encrypts:

        - `responseToClient` with the AS–Client symmetric key.

        - `TGT` with the AS–TGS symmetric key (and again with AS–Client for the demo).

    - Sends the resulting `UTicket` back via `Messenger.ticketResponder`.

#### 2.2.2 Ticket Granting Server (TGS)

1. `Controllers.Kerberos.TGS.Controller`

   Similar structure to `AS.Controller`:

    - Configures port (e.g. `1202`) and paths.

    - Creates a `ServerSocket`.

    - Loops accepting connections and delegating to `TGS.ProcessRequest`.

2. `Controllers.Kerberos.TGS.ProcessRequest`

   Implements TGS-REQ → TGS-REP logic:

    - Accepts a `UTicket` containing:

        - `TGT` (from AS).

        - `auth` (client authenticator encrypted with `K_c`,`tgs`).

        - request4TGS (desired service ID).

    - Decrypts `TGT` using the TGS–AS key, recovers `K_c`,`tgs`.

    - Decrypts auth using `K_c`,`tgs`.

    - Validates:

        - Client IDs match in TGT and authenticator.

        - Ticket lifetime is still valid.

        - Client IP matches the socket.

    - Generates session key `K_c`,`s` for Client–Server.

    - Constructs:

        - `responseToClient` (for the client, with `K_c`,`s`).

        - `serviceTicket` (for the Server).

    - Encrypts:

        - `responseToClient` with `K_c`,`tgs`.

        - `serviceTicket` with the TGS–Server key (and additionally with `K_c`,`tgs`).

    - Sends the `UTicket` back via `Messenger.ticketResponder`.

#### 2.2.3 Application Server

1. `Controllers.Kerberos.Server.Controller`

    - Configures:

        - `projectPath`.

        - `addressIP_Self` (e.g. "`localhost`").

        - Receiving port (e.g. `1203`).

        - Path to `SecretVault/Connection/` (server’s shared keys).

    - Creates a `ServerSocket`.

    - Loops:

        - Accepts incoming connections.

        - Calls `Server.ProcessRequest.processUserRequest(socket, path4SecretKeyRetrieving, addressIP_Self)`.

2. Controllers.Kerberos.Server.ProcessRequest

   Implements AP-REQ → AP-REP logic:

    - Receives a `UTicket` containing:

        - `serviceTicket`.

        - `auth` (client authenticator).

    - Decrypts `serviceTicket` using the Server–TGS key, recovers `K_c`,`s`.

    - Checks ticket lifetime.

    - Decrypts `auth` using `K_c`,`s`.

    - Validates:

        1. Client identity matches between `serviceTicket` and `auth`.

        2. The `serviceTicket` is addressed to this server.

        3. IP address matches.

      If valid:

        - Calls `approveSession(...)`:

            - Builds a new `UTicket` containing one auth ticket (service authenticator).

            - Encrypts it with `K_c`,`s`.

            - Sends it via `Messenger.ticketResponder`.

      If invalid:

        - Sends false via `Messenger.booleanResponder`.

#### 2.2.4 Client

1. `Controllers.Kerberos.Client.Controller`

   Acts as the demo driver:

    - Sets:

        - `projectPath`.

        - Client identity (`whoAmI = "Client"`).

        - Local IP (e.g. "`localhost`").

        - AS/TGS/Server addresses and ports.

    - Loads the long-term symmetric key Client–AS from `SecretVault/Connection`.

    - Orchestrates the three Kerberos steps using `RequestAccess`:

        1. AS step:

            - Calls `RequestAccess.startAuth(...)` → AS-REQ.

            - Receives AS-REP as a `UTicket`.

            - Decrypts `responseToClient` and `TGT` with Client–AS key.

            - Extracts `K_c`,`tgs` and persists it.

        2. TGS step:

            - Calls `RequestAccess.followTGS(...)`:

            - Includes `TGT`, a new `auth` and `request4TGS`.

            - Encrypts `auth` with `K_c`,`tgs` and sends TGS-REQ.

            - Receives TGS-REP as a `UTicket`.

            - Decrypts `responseToClient` and `serviceTicket` using `K_c`,`tgs`.

            - Extracts `K_c`,`s` and persists it.

        3. Server step:

            - Calls `RequestAccess.askForService(...)`:

            - Includes `serviceTicket` and a new `auth` encrypted with `K_c`,`s`.

            - Receives AP-REP as a `UTicket`.

            - Decrypts it using `K_c`,`s`.

    - Prints decrypted tickets to the console for inspection.

2. `Controllers.Kerberos.Client.RequestAccess`

   Small helper with three methods:

- `startAuth(...)`:

    - Builds a `UTicket` with `generateRequest(...)` (id "`request`").

    - Sends it to the AS using `Messenger.ticketSender(...)`.

- `followTGS(...)`:

    - Takes `ticketFromAS` and extracts the `TGT`.

    - Creates a new `UTicket`:

        - Adds `TGT`.

        - Adds `request4TGS` (desired service ID).

        - Adds an `auth` ticket (client id, client IP, timestamp).

    - Encrypts `auth` with `K_c`,`tgs`.

    - Sends to the TGS via `Messenger.ticketSender(...)`.

- `askForService(...)`:

    - Takes `ticketFromTGS` and extracts the `serviceTicket`.

    - Creates a new `UTicket`:

        - Adds `serviceTicket`.

        - Adds an `auth` ticket (client id, client IP, timestamp).

    - Encrypts `auth` with `K_c`,`s`.

    - Sends to the Server via `Messenger.ticketSender(...)`.

----

### 3. Model layer

#### 3.1 `Ticket` and `UTicket`

1. `Model.Ticket`

   A serializable POJO representing a single Kerberos-like ticket with fields:

    - `idTicket` – logical name ("`request`", "`TGT`", "`auth`", etc.).

    - `firstId` / `secondId` – generic IDs (client, server, TGS).

    - `addressIP` – client IP.

    - `lifetime` – ticket lifetime as `String`.

    - `timeStamp` – issuance or authenticator timestamp.

    - `key` – session key in Base64 string form.

   Includes helper methods to check which fields are filled.

2. `Model.UTicket`

   A serializable envelope that carries one or more `Ticket` instances over
   the network. Main responsibilities:

    - Maintain a `List<Ticket>`.

    - Create standard tickets:

        - `generateRequest(...)` – initial request ticket (client → AS).

        - `generateResponse4User(...)` – responseToClient.

        - `generateTicket(...)` – generic ticket factory.

        - `request4TGS(...)` – ticket used to ask TGS for a service.

        - `addAuthenticator(...)` – create an auth ticket.

    - Encryption and decryption of tickets:

        - `encryptTicket(SecretKey key, String id)` – encrypt only existing fields
          of the ticket with given id using DES.

        - `decryptTicket(SecretKey key, String id)` – inverse operation.

    - Debug helpers:

        - `printTicket(UTicket)` – print all tickets.

        - `printTicket(UTicket, String)` – print a specific ticket.

   `UTicket` is the main unit of data sent over the network via Messenger.

----

#### 3.2 Messenger

`Model.Messenger`

Encapsulates all low-level networking operations. Main methods:

- Socket setup:

    - `socketInitializer(host, port)` – creates a client `Socket`.

    - `serverSocketInitializer(port)` – creates a `ServerSocket`.

    - `requestAccepter(ServerSocket)` – accepts an incoming connection.

- Key-level operations:

    - `receivePublic(Socket)` – reads a `KeyObject` and returns a `PublicKey`.

    - `sendPublicReceiveSecret(...)` – sends a public key, receives an encrypted symmetric key, and returns a
      `SecretKey`.

    - `secretResponder(...)` – encrypts a symmetric key with a public key and sends it inside a `KeyObject`.

- Ticket-level operations:

    - `ticketSender(host, port, UTicket)` – connect, send a `UTicket`, wait for a `UTicket` response, then close the
      socket.

    - `ticketAccepter(Socket)` – read a `UTicket` from the socket.

    - `ticketResponder(Socket, UTicket)` – send a `UTicket` back and close the socket.

    - `booleanResponder(Socket, boolean)` – send a boolean and close.

`Messenger` is deliberately generic: it does not know Kerberos semantics; it only
knows how to send/receive objects (tickets/keys) over sockets.

----

#### 3.3 KeyDistributor and KeyObject

1. `Model.KeyDistributor`

   A helper used in the Distributor phase:

    - `publicSenderSecretReceiver(...)`:

      Client side of the handshake:

        - Opens a `Socket` to the receiver.

        - Loads local RSA keys.

        - Uses `Messenger.sendPublicReceiveSecret` to:

            - Send public key.

            - Receive an encrypted symmetric key.

        - Saves the resulting symmetric key in `SecretVault/Connection`.

    - `receiver(...)`:

      Server side of the handshake:

        - Accepts a connection on a `ServerSocket`.

        - Receives the remote public key via `Messenger.receivePublic`.

        - Saves the received public key into `SecretVault/Connection`.

        - Generates a new symmetric key.

        - Saves it in `SecretVault/Connection`.

        - Sends it back, encrypted with the received public key, via `Messenger.secretResponder`.

2. `Model.KeyObject`

   A simple serializable container used during key exchange:

    - `publicKey` – Base64-encoded string of a public key.

    - `secretKey` – Base64-encoded string of a symmetric key.

   It allows both public and secret keys to travel over the object stream, without
   coupling network code to specific key classes.

----

#### 3.4 TimeMethods

`Model.TimeMethods`

Utility methods around `Timestamp` and durations, used to implement lifetimes
and timestamps in tickets:

- `timeSignature()` / `timeSignatureInString()` – current time.

- `timeStamp2String(...)` / `string2TimeStamp(...)` – conversions.

- `getMillis(...)` – helper overloads to compute millisecond durations from days/hours/minutes/seconds.

The production of lifetime values in tickets is all based on these helpers.

----

### 4. Security layer (overview)

The `Security.Model` package provides cryptographic primitives:

- `Security.Model.Encryption`

    - Wrapper around Cipher calls:

        - `publicEncrypt(PublicKey, String)` / `privateDecrypt(PrivateKey, String)` using "`RSA`".

        - `symmetricEncrypt(SecretKey, String)` / `symmetricDecrypt(SecretKey, String)` using "`DES`".

    - Encodes encrypted data in `Base64` for easy transport/storage.

- `Security.Model.KeyMethods`

    - Key generation:

        - `keyCreator(path, whoAreYou)` – generate RSA key pair for a role.

        - `generateSecretKey()` – generate a DES key.

    - Persistence:

        - `saveKey(...)`, `saveSecret(...)` – save keys to files.

        - `recoverPublic(...)`, `recoverPrivate(...)`, `recoverSecret(...)` – load keys from files.

    - Conversion:

        - `convertAnyKey2String(Key)` – `Base64` encode `Key.getEncoded()`.

        - `convertString2Public(String)` / `convertString2Key(String)` – `Base64` decode to keys.

The concrete details of algorithms (RSA, DES) and their limitations belong in the dedicated cryptography or limitations
documentation; here they are part of the architecture only in that they define where keys come from and how they are
stored.