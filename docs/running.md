# Running the Kerberos Demo

This document explains how to run the project locally and (optionally) in a
multi-node setup. It focuses on the **order of processes**, the use of the
`Distributor` package for key setup, and the `Kerberos` controllers for the
actual authentication flow.

The goal is to provide a repeatable way to demonstrate a Kerberos-style,
zero-trust architecture using this codebase.

---

## 0. Prerequisites and assumptions

- Java 8+ installed and on your `PATH`.
- The project has been cloned with the directory structure intact:

  - `java/Controllers/...`
  - `java/Model/...`
  - `java/Security/...`
  - `java/Security/SecretVault/Generated/`
  - `java/Security/SecretVault/Connection/`

- You are running from an IDE (e.g., IntelliJ IDEA) or have a way to run the
  main classes directly.

### SecretVault directory state

- For a clean run, start with **empty** directories:

  - `Security/SecretVault/Generated/`
  - `Security/SecretVault/Connection/`

  Any existing `.key` files will be overwritten by the `Distributor` phase
  when keys are regenerated.

### Default paths and ports

Each controller hardcodes:

- A `projectPath`, e.g.:

  ```java
  String projectPath = "C:\SecureExchange\Kerberos";
  ```

- A listening or connection port, e.g.:

  ```java
  int receivingPort = 1121; // AS
  int receivingPort = 1202; // TGS
  int receivingPort = 1203; // Server
  ```

To run on your own machine:

1. Update the `projectPath` at the top of each `Controller` / `KeyCreation` /
   `Sender` / `Receiver` class to match your local checkout.
2. Optionally adjust ports if needed (just keep them consistent between
   sender and receiver for each pair).

---

## 1. Process overview

There are two main phases:

1. **Distributor phase** – cryptographic bootstrap
   - Generates RSA key pairs for each principal (AS, TGS, Server, Client).
   - Performs pairwise key exchange to establish long-term symmetric keys
     (e.g., AS–Client, AS–TGS, TGS–Server).
   - Uses classes in `Controllers.Distributor.*` and `Model.KeyDistributor`.

2. **Kerberos phase** – authentication protocol
   - Runs the AS, TGS and Server network services.
   - Runs the Client to execute the AS-REQ, TGS-REQ and AP-REQ flows.
   - Uses classes in `Controllers.Kerberos.*`.

General rule for **any network interaction** in this project:

> **Always start the Receiver (server-side) first, then the Sender (client-side).**

If you start a Sender before the corresponding Receiver is listening, the TCP
connection will fail.

---

## 2. Single-VM demo (localhost)

This is the simplest way to see the system working end-to-end. All four roles
run on the same machine in separate JVMs.

### 2.1 Step 1 – Generate RSA key pairs (KeyCreation)

For each principal (AS, TGS, Server, Client), run its `KeyCreation` class
under `Controllers.Distributor` **once**:

- `Controllers.Distributor.AS.KeyCreation`
- `Controllers.Distributor.TGS.KeyCreation`
- `Controllers.Distributor.Server.KeyCreation`
- `Controllers.Distributor.Client.KeyCreation`

Each `KeyCreation`:

- Uses `Security.Model.KeyMethods.keyCreator(...)` to generate:
  - `public<Principal>.key`
  - `private<Principal>.key`
- Saves them under:

  ```text
  Security/SecretVault/Generated/
  ```

If you change the `projectPath`, ensure all `KeyCreation` classes use the same
absolute or relative base path so keys end up in the correct folder.

You only need to rerun this step when you want to **rotate** RSA key pairs.

### 2.2 Step 2 – Establish symmetric keys (Distributor Sender/Receiver)

Next, you must perform an initial **key distribution** phase for each pair of
principals that need a long-term symmetric key.

This is handled by:

- `Controllers.Distributor.<Principal>.Receiver`
- `Controllers.Distributor.<Principal>.Sender`
- `Model.KeyDistributor`

Conceptually, for each pair `A` and `B`:

1. Start `Receiver` on the principal that will **generate** the symmetric key.
2. Then start `Sender` on the principal that will connect and receive it.

The concrete classes in this project follow a specific mapping (e.g. TGS ↔ AS,
TGS ↔ Server, AS ↔ Client, etc.). The **pattern** is always:

1. **Receiver side** (must be started first):

   ```java
   ServerSocket serverSocket = new ServerSocket(<port>);
   KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving);
   ```

   This:

   - Listens on `<port>`.
   - Accepts the peer’s public key.
   - Saves the peer’s public key as `public<Peer>Received.key` under
     `SecretVault/Connection/`.
   - Generates a fresh symmetric key (e.g. DES).
   - Saves it as `Symmetric-<whoAmI>-<peer>.key`.
   - Sends the symmetric key back encrypted with the peer’s RSA public key.

2. **Sender side**:

   ```java
   KeyDistributor.publicSenderSecretReceiver(
       receiverHost,
       connectionPort,
       receiverName,    // who is responding
       whoAmI,          // who is sending
       path4KeyRetrieval,
       path4KeySaving
   );
   ```

   This:

   - Connects to the Receiver’s `<host>:<port>`.
   - Loads its own RSA key pair from `SecretVault/Generated/`.
   - Sends its public key and awaits the encrypted symmetric key.
   - Decrypts it with its private RSA key.
   - Saves it as `Symmetric-<whoAmI>-<receiverName>.key` under
     `SecretVault/Connection/`.

For the **demo to work out of the box**, you need at least these symmetric
links established:

- AS ↔ Client (e.g. `Symmetric-AS-Client.key`, `Symmetric-Client-AS.key`)
- AS ↔ TGS (e.g. `Symmetric-AS-TGS.key`, `Symmetric-TGS-AS.key`)
- TGS ↔ Server (e.g. `Symmetric-TGS-Server.key`, `Symmetric-Server-TGS.key`)

Run the corresponding `Receiver` then `Sender` classes for each pair,
following the same pattern as the examples in `Controllers.Distributor.*`.

> **Important:** On a single VM, all principals may share the same
> `SecretVault/Connection` directory. In a real distributed setup, each
> principal would only see *its own* filesystem and keys.

You only need to rerun this step when you want to **rotate** symmetric keys or
when starting from a clean `SecretVault/Connection` directory.

### 2.3 Step 3 – Start Kerberos services (AS, TGS, Server)

Now start the actual Kerberos network services in separate JVMs, **in this order**:

1. **Authentication Server (AS)**

   - Main class:
     - `Controllers.Kerberos.AS.Controller`
   - Default port: `1121`
   - Uses paths:
     - `SecretVault/Generated/` (its own generated keys)
     - `SecretVault/Connection/` (symmetric keys with Client and TGS)

   This process:

   - Opens a `ServerSocket` on `1121` using `Messenger.serverSocketInitializer`.
   - Loops forever accepting connections:
     - For each connection, calls
       `AS.ProcessRequest.processUserRequest(...)` to handle AS-REQ.
   - Issues TGTs and `K_c,tgs` to clients.

2. **Ticket Granting Server (TGS)**

   - Main class:
     - `Controllers.Kerberos.TGS.Controller`
   - Default port: `1202`
   - Uses paths:
     - `SecretVault/Connection/` (keys with AS and Client)
     - `SecretVault/Generated/` (its own generated keys if needed)

   This process:

   - Opens a `ServerSocket` on `1202`.
   - Loops accepting connections:
     - For each connection, calls
       `TGS.ProcessRequest.processUserRequest(...)` to handle TGS-REQ.
   - Issues service tickets and `K_c,s` to clients.

3. **Application Server**

   - Main class:
     - `Controllers.Kerberos.Server.Controller`
   - Default port: `1203`
   - Uses paths:
     - `SecretVault/Connection/` (keys with TGS and Client)

   This process:

   - Opens a `ServerSocket` on `1203`.
   - Loops accepting connections:
     - For each connection, calls
       `Server.ProcessRequest.processUserRequest(...)` to handle AP-REQ.
   - Verifies service tickets and authenticators, then returns AP-REP.

Make sure all three services report that they have been successfully started
(e.g., `"AS iniciado."`, `"TGS iniciado."`, `"Servidor iniciado."` in the console).

### 2.4 Step 4 – Run the Client

Finally, run the Client:

- Main class:
  - `Controllers.Kerberos.Client.Controller`

This process:

1. Loads the long-term symmetric key `K_as,c` from
   `SecretVault/Connection/` via `KeyMethods.recoverSecret("Client", "AS")`.
2. Constructs an AS-REQ using `RequestAccess.startAuth(...)` and sends it to
   the AS (`localhost:1121` by default).
3. Receives AS-REP, decrypts it, and extracts `K_c,tgs`.
4. Constructs a TGS-REQ using `RequestAccess.followTGS(...)` and sends it to
   the TGS (`localhost:1202` by default).
5. Receives TGS-REP, decrypts it, and extracts `K_c,s`.
6. Constructs an AP-REQ using `RequestAccess.askForService(...)` and sends it
   to the Server (`localhost:1203` by default).
7. Receives AP-REP, decrypts it, and prints the server’s authenticator.

You should see console output walking you through each ticket being created,
encrypted, decrypted and validated.

---

## 3. Multi-node deployment (conceptual)

To run each principal on a separate machine in an insecure LAN:

1. **Copy the code** to each machine and adjust `projectPath` in the classes
   for that principal.
2. Ensure that each machine has its own `SecretVault/Generated/` and
   `SecretVault/Connection/` directories.
3. For each pair of principals that must share a symmetric key:
   - Choose a machine to run the `Receiver` for that pair.
   - Start the `Receiver` on that machine and port.
   - Start the `Sender` on the peer machine, pointing to that host/IP and port.
4. Update IP/host fields in controllers:
   - For example, in `Client.Controller`:

     ```java
     String addressIP_AS     = "<AS-host-IP>";
     String addressIP_TGS    = "<TGS-host-IP>";
     String addressIP_Server = "<Server-host-IP>";
     ```

5. Open firewall rules for the chosen ports (e.g. `1121`, `1202`, `1203`).
6. Start AS, TGS, Server each on their respective machines.
7. Start the Client on its own machine and observe the same Kerberos flow,
   now crossing the network instead of using `localhost`.

> In a **real deployment**, each principal would only see *its own* key files
> (its own `Generated/` and its own view of `Connection/`). In this demo, the
> same directory structure is reused for simplicity.

---

## 4. Regenerating or rotating keys

If you want to **regenerate all keys**:

1. Stop all running JVM processes (Client, Server, TGS, AS, Distributor).
2. Delete the contents of:
   - `Security/SecretVault/Generated/`
   - `Security/SecretVault/Connection/`
3. Rerun:
   - All `KeyCreation` classes (Section 2.1).
   - All required Distributor `Receiver`/`Sender` pairs (Section 2.2).
4. Restart AS, TGS, Server and Client (Sections 2.3–2.4).

If you only regenerate a subset of keys, you may break the trust relationships
between principals. For demonstration purposes, it is usually simplest to
clear all `.key` files and start from scratch.

---

## 5. Common issues

- **`No se ha podido iniciar el Servidor.`**
  - The requested port is already in use.
  - Another instance is still running.
  - Fix: stop the old process or change the port.

- **`FileNotFoundException` when reading `.key` files**
  - Distributor phase was not run for that pair.
  - `projectPath` or directory structure is incorrect.
  - Fix: verify paths in the controller, rerun `KeyCreation` and the appropriate
    `Receiver`/`Sender` pair.

- **Client hangs or gets an error connecting**
  - Target host is wrong (`addressIP_*` not updated).
  - Receiver process (AS/TGS/Server) is not running yet.
  - Fix: double-check IP/host and order (Receiver before Sender / Client).

Once these pieces are in place, you can reliably demonstrate the end-to-end
Kerberos-style authentication flow either on a single VM or across multiple
nodes in a zero-trust LAN.
