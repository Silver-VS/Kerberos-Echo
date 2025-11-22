# Java Zero-Trust Auth

## Kerberos Echo

> In Greek myth, Echo is the nymph who can only repeat others’ words.
> 
> This is an echo of the real Kerberos: it imitates behavior, but it has no power of its own.

This project is a bare-bones Kerberos-style authentication system implemented in Java.

It is designed as an educational demo of how multiple roles (Client, AS, TGS, Server)
can authenticate and communicate securely over an **insecure or zero-trust network**.

The focus is on:
- The **architecture** (roles and separation of concerns).
- The **networked nature** (each role as an independent process).
- The **Kerberos protocol sequence** (AS-REQ/AS-REP, TGS-REQ/TGS-REP, AP-REQ/AP-REP).

> This is a teaching/demo project. 
> 
> Cryptographic choices and security hardening are intentionally simplified. 


> Do not use this code in production.

> For detailed architecture, protocol description and design notes, see docs ([docs/intro.md](docs/intro.md))
---

## Configuration

At the top of each controller you can adjust:

- `projectPath` – base path to the project on this machine.
- SecretVault paths – where keys are stored.
- Addresses and ports – to move from `localhost` to a real LAN.

Example (TGS):

```java
int receivingPort = 1202;
String projectPath = "DISK:\\PATH";

String path4SecretKeyRetrieving =
    projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";
String path4SecretKeySaving =
    projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
```
---

## Quick Start (single machine)

1. Clone the repository and open it in your IDE (e.g. IntelliJ IDEA).

2. Ensure the following directories exist and are empty:
    - `src/main/java/Security/SecretVault/Generated`
    - `src/main/java/Security/SecretVault/Connection`

3. Run RSA key creation for each role (once):
    - `Controllers.Distributor.AS.KeyCreation`
    - `Controllers.Distributor.TGS.KeyCreation`
    - `Controllers.Distributor.Server.KeyCreation`
    - `Controllers.Distributor.Client.KeyCreation`

4. Run the Distributor key-exchange pairs (**Receiver first, then Sender**) to establish
   symmetric keys between roles (AS–Client, AS–TGS, TGS–Server, etc.).

5. Start the Kerberos services:
    - `Controllers.Kerberos.AS.Controller`
    - `Controllers.Kerberos.TGS.Controller`
    - `Controllers.Kerberos.Server.Controller`

6. Run the client:
    - `Controllers.Kerberos.Client.Controller`

You should see the tickets and responses printed in the consoles of each role
showing the full Kerberos-style handshake.

---

## Further documentation

For detailed architecture, protocol description and design notes, see:

[Technical Docs](docs/intro.md)