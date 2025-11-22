# Kerberos-style Protocol Flow

This document describes the end-to-end authentication flow implemented in this
project: how the Client, AS, TGS and Server exchange tickets and keys over the
network.

It maps the classic Kerberos steps:

1. **AS-REQ / AS-REP** – Client ↔ Authentication Server (AS)
2. **TGS-REQ / TGS-REP** – Client ↔ Ticket Granting Server (TGS)
3. **AP-REQ / AP-REP** – Client ↔ Application Server

to the concrete Java classes and methods in this codebase.

---

## 1. Core concepts and message types

### 1.1 Tickets and UTickets

Two model classes represent the protocol payloads:

- `Model.Ticket`
- `Model.UTicket`

#### `Ticket`

A `Ticket` is a serializable POJO with generic fields:

```java
public class Ticket implements Serializable {
    private String idTicket;   // Logical name: "request", "TGT", "auth", etc.
    private String firstId;    // Typically client ID or service ID
    private String secondId;   // Typically peer ID (TGS, Server, etc.)
    private String addressIP;  // Client IP address
    private String lifetime;   // Lifetime as String (Timestamp.toString())
    private String timeStamp;  // Issuance / authenticator timestamp
    private String key;        // Session key (Base64-encoded)
    // + getters, setters, "isFilled*" helpers
}
```

`Ticket` itself has no protocol logic; it is a container for Kerberos-like data.

#### `UTicket`

A `UTicket` is a **bundle** of one or more `Ticket` objects:

```java
public class UTicket implements Serializable {
    private final ArrayList<Ticket> tickets;
    // ...
}
```

Responsibilities:

- Store multiple `Ticket` instances.
- Provide helpers to create standard tickets:
    - `generateRequest(...)`       → `"request"`
    - `generateResponse4User(...)` → `"responseToClient"`
    - `generateTicket(...)`        → generic ticket
    - `request4TGS(...)`           → `"request4TGS"`
    - `addAuthenticator(...)`      → `"auth"`
- Provide **symmetric encryption / decryption** for a specific ticket:
    - `encryptTicket(SecretKey key, String id)`
    - `decryptTicket(SecretKey key, String id)`
- Provide debug printing:
    - `printTicket(UTicket)`
    - `printTicket(UTicket, String ticketId)`

All protocol messages sent over the network are serialized `UTicket` instances.

---

### 1.2 Ticket IDs and their meaning

The `idTicket` field is used to distinguish logical roles of tickets:

| `idTicket`           | Producer         | Main use                                                        |
|----------------------|------------------|------------------------------------------------------------------|
| `"request"`          | Client           | Initial request to AS (user ID, requested service, lifetime)    |
| `"TGT"`              | AS               | Ticket-Granting Ticket (Client ↔ TGS)                           |
| `"request4TGS"`      | Client           | Request to TGS for a specific service                           |
| `"responseToClient"` | AS, TGS, Server  | Human-readable “front” ticket for client (session keys, TS)     |
| `"serviceTicket"`    | TGS              | Service ticket (Client ↔ Server)                                |
| `"auth"`             | Client, Server   | Authenticator: proves recent activity and binds to client IP    |

Each ticket reuses generic fields:

- `firstId` / `secondId`
- `addressIP`
- `lifetime`
- `timeStamp`
- `key`

with semantics defined by the context (AS vs TGS vs Server).

---

### 1.3 Key notation (conceptually)

For readability, the docs use Kerberos-style notation:

- `K_c,tgs` – session key between Client and TGS
- `K_c,s` – session key between Client and Server
- `K_as,c` – long-term symmetric key AS–Client
- `K_as,tgs` – long-term symmetric key AS–TGS
- `K_tgs,s` – long-term symmetric key TGS–Server

In code, these are all `SecretKey` instances stored in the filesystem (`SecretVault`)
under names such as:

- `Symmetric-AS-Client.key` (for `K_as,c` on the AS side)
- `Symmetric-Client-AS.key` (same key, on the Client side)
- `Symmetric-AS-TGS.key`, `Symmetric-TGS-AS.key`
- `Symmetric-TGS-Server.key`, `Symmetric-Server-TGS.key`
- etc.

The actual crypto is done with DES via `Security.Model.Encryption.symmetricEncrypt`
/ `symmetricDecrypt`.

---

### 1.4 Transport

All messages travel over plain TCP sockets as serialized Java objects:

- `Model.Messenger.ticketSender(...)` – client side send + receive.
- `Model.Messenger.ticketAccepter(...)` – server side receive.
- `Model.Messenger.ticketResponder(...)` – server side send.

Each protocol step is a single request/response round-trip:

1. Client connects, sends a `UTicket`.
2. Server processes, sends back a `UTicket` or boolean.
3. Connection is closed.

There is no persistent connection between steps.

---

## 2. Step 1 – AS-REQ / AS-REP

### 2.1 Client → AS: AS-REQ

Entry point: `Controllers.Kerberos.Client.Controller`.

Key pieces:

```java
String whoAmI = "Client";
String addressIP_AS = "localhost";
int connectionPort_AS = 1121;

SecretKey ClientAS =
    KeyMethods.recoverSecret(path4SecretKeyComms, whoAmI, "AS");

Timestamp requestedLifetime = TimeMethods.timeSignature();
requestedLifetime.setTime(
    requestedLifetime.getTime() + TimeMethods.getMillis(5, 0)
);

UTicket responseFromAS = RequestAccess.startAuth(
    whoAmI,
    "AS",                         // serviceID (as used in this demo)
    requestedLifetime.toString(), // requested lifetime
    addressIP_AS,
    connectionPort_AS
);
```

Client builds and sends AS-REQ via `RequestAccess.startAuth`:

```java
public static UTicket startAuth(
        String userID,
        String serviceID,
        String requestedLifetime,
        String addressIP_AS,
        int connectionPort_AS) {

    UTicket serviceRequest = new UTicket();
    serviceRequest.generateRequest(userID, serviceID, requestedLifetime);
    return Messenger.ticketSender(addressIP_AS, connectionPort_AS, serviceRequest);
}
```

Resulting AS-REQ payload (`UTicket`):

- Contains one `Ticket` with `idTicket = "request"`:
    - `firstId`   → client ID (`userID`)
    - `secondId`  → requested service (`serviceID`, here `"AS"`)
    - `lifetime`  → requested lifetime
- No authentication yet; this is a simplified demo.

### 2.2 AS processes AS-REQ

Entry point: `Controllers.Kerberos.AS.Controller`:

```java
do {
    Socket clientSocket = Messenger.requestAccepter(serverSocket);
    ProcessRequest.processUserRequest(
        clientSocket,
        path4SecretKeySaving,   // Generated/
        path4SecretKeyComms     // Connection/
    );
} while (!serverSocket.isClosed());
```

Main logic: `Controllers.Kerberos.AS.ProcessRequest`:

```java
public static boolean processUserRequest(
        Socket socket,
        String path4KeySaving,
        String path4KeyRetrieving) {

    UTicket userRequest = Messenger.ticketAccepter(socket);
    Ticket ticket = userRequest.searchTicket("request");
    UTicket userResponse = new UTicket();
    // ...
}
```

Steps:

1. **Receive AS-REQ** (`UTicket`) via `Messenger.ticketAccepter`.
2. Extract `"request"` ticket:
    - Contains client ID (`ticket.getFirstId()`).
3. Generate session key `K_c,tgs`:

   ```java
   SecretKey sessionKeyClientTGS = KeyMethods.generateSecretKey();
   KeyMethods.saveSecret(sessionKeyClientTGS,
                         path4KeySaving, "Client", "TGS");
   ```

4. Compute timestamps:

   ```java
   Timestamp timestamp = Timestamp.from(Instant.now());
   Timestamp lifetime  = new Timestamp(
       timestamp.getTime() + TimeMethods.getMillis(5, 0)
   );
   ```

5. Build **AS-REP payload** (`UTicket`):

    - `responseToClient` (id `"responseToClient"`):

      ```java
      userResponse.generateResponse4User(
          "TGS - Victor",              // ID of TGS
          timestamp.toString(),        // TS2
          lifetime.toString(),         // ticket lifetime
          KeyMethods.convertAnyKey2String(sessionKeyClientTGS) // K_c,tgs
      );
      ```

    - `TGT` (Ticket-Granting Ticket, id `"TGT"`):

      ```java
      userResponse.generateTicket(
          "TGT",                                   // idTicket
          ticket.getFirstId(),                    // ID_c
          "TGS - Victor",                         // ID_tgs
          timestamp.toString(),                   // TS2
          socket.getInetAddress().getHostAddress(), // AD_c
          lifetime.toString(),                    // lifetime
          KeyMethods.convertAnyKey2String(sessionKeyClientTGS) // K_c,tgs
      );
      ```

6. Retrieve long-term keys:

   ```java
   SecretKey secretAS_Client = KeyMethods.recoverSecret(
       path4KeyRetrieving, "AS", "Client"
   );
   SecretKey secretAS_TGS = KeyMethods.recoverSecret(
       path4KeyRetrieving, "AS", "TGS"
   );
   ```

7. Encrypt tickets:

   ```java
   userResponse.encryptTicket(secretAS_Client, "responseToClient");
   userResponse.encryptTicket(secretAS_TGS,    "TGT");
   userResponse.encryptTicket(secretAS_Client, "TGT"); // demo: also with AS-Client
   ```

   Conceptually:

    - `responseToClient` → encrypted with `K_as,c`.
    - `TGT`              → encrypted for TGS with `K_as,tgs` (and also with `K_as,c`
      in this demo so the client can inspect it, which is not how real Kerberos behaves).

8. Send AS-REP back:

   ```java
   return Messenger.ticketResponder(socket, userResponse);
   ```

### 2.3 Client processes AS-REP

Back in `Client.Controller`:

```java
if (responseFromAS.decryptTicket(ClientAS, "responseToClient")) { ... }
if (responseFromAS.decryptTicket(ClientAS, "TGT")) { ... }

Ticket responseAS = responseFromAS.searchTicket("responseToClient");
SecretKey sessionKeyClientTGS =
    KeyMethods.convertString2Key(responseAS.getKey());

KeyMethods.saveSecret(sessionKeyClientTGS,
                      path4SecretKeyComms, "Client", "TGS");
```

Client:

1. Decrypts `responseToClient` and `TGT` with `K_as,c` (`ClientAS` key).
2. Extracts `K_c,tgs` from `responseToClient.key`.
3. Saves `K_c,tgs` in its own SecretVault as `Symmetric-Client-TGS.key`.

The client is now ready to talk to the TGS.

---

## 3. Step 2 – TGS-REQ / TGS-REP

### 3.1 Client → TGS: TGS-REQ

From `Client.Controller`:

```java
System.out.println("Solicitud al TGS");

UTicket responseFromTGS =
    RequestAccess.followTGS(
        responseFromAS,                // contains TGT + responseToClient
        "Server",                      // serviceID
        sessionKeyClientTGS,           // K_c,tgs
        responseAS.getLifetime(),      // requested lifetime
        whoAmI,                        // userID
        TimeMethods.timeSignature().toString(),
        addressIP_Self,                // client IP
        addressIP_TGS,
        connectionPort_TGS
    );
```

Implementation (`RequestAccess.followTGS`):

```java
public static UTicket followTGS(
        UTicket ticketFromAS,
        String serviceID,
        SecretKey sessionKeyClientTGS,
        String requestedLifetime,
        String userID,
        String timeStamp,
        String addressIP_Self,
        String addressIP_TGS,
        int connectionPort_TGS) {

    UTicket followUpTicketTGS = new UTicket();

    // Reuse TGT from AS-REP
    followUpTicketTGS.addTicket(
        ticketFromAS.searchTicket("TGT")
    );

    // Request specific service from TGS
    followUpTicketTGS.request4TGS(serviceID);   // idTicket = "request4TGS"

    // Add authenticator (auth)
    followUpTicketTGS.addAuthenticator(userID, addressIP_Self, timeStamp);

    System.out.println("Tickets a enviar:
");
    followUpTicketTGS.printTicket(followUpTicketTGS);

    if (followUpTicketTGS.encryptTicket(sessionKeyClientTGS, "auth"))
        System.out.println("
Ticket auth encriptado exitosamente con llave de sesión Client - TGS");
    else {
        System.out.println("
Ha ocurrido un error al encriptar el ticket auth.");
        System.exit(-1);
    }

    try {
        return Messenger.ticketSender(addressIP_TGS, connectionPort_TGS, followUpTicketTGS);
    } catch (Exception e) {
        System.out.println("Error al recibir respuesta.");
        System.out.println("Error: ");
        e.printStackTrace();
        return null;
    }
}
```

Payload (TGS-REQ):

- `TGT` (from AS).
- `request4TGS` (service ID).
- `auth`:

    - `idTicket`  → `"auth"`
    - `firstId`   → client ID
    - `addressIP` → client IP
    - `timeStamp` → current time
    - encrypted with `K_c,tgs`.

### 3.2 TGS processes TGS-REQ

Entry point: `Controllers.Kerberos.TGS.Controller`:

```java
do {
    Socket clientSocket = Messenger.requestAccepter(serverSocket);
    ProcessRequest.processUserRequest(
        clientSocket,
        path4SecretKeyRetrieving, // Connection/
        path4SecretKeySaving      // Generated/
    );
} while (!serverSocket.isClosed());
```

Logic: `Controllers.Kerberos.TGS.ProcessRequest`:

Key steps:

1. **Receive TGS-REQ**:

   ```java
   UTicket userRequest = Messenger.ticketAccepter(socket);
   ```

2. **Recover TGS–AS key** and decrypt TGT:

   ```java
   SecretKey secretKeyTGS_AS =
       KeyMethods.recoverSecret(path4KeyRetrieving, "TGS", "AS");

   userRequest.decryptTicket(secretKeyTGS_AS, "TGT");
   Ticket tgt = userRequest.searchTicket("TGT");
   ```

3. **Recover `K_c,tgs` from TGT** and save TGS–Client view:

   ```java
   SecretKey sessionKeyTGS_Client =
       KeyMethods.convertString2Key(tgt.getKey());
   KeyMethods.saveSecret(sessionKeyTGS_Client,
                         path4KeyRetrieving, "TGS", "Client");
   ```

4. **Decrypt authenticator (`auth`)** with `K_c,tgs`:

   ```java
   userRequest.decryptTicket(sessionKeyTGS_Client, "auth");
   Ticket userService = userRequest.searchTicket("request4TGS");
   Ticket userAuth    = userRequest.searchTicket("auth");
   ```

5. **Validate client identity, lifetime and IP**:

   ```java
   if (tgt.getFirstId().equals(userAuth.getFirstId())) {

       Timestamp lifetime = TimeMethods.string2TimeStamp(tgt.getLifetime());
       Timestamp now      = TimeMethods.timeSignature();

       if (now.compareTo(lifetime) < 0) {

           if (tgt.getAddressIP().equals(
               socket.getInetAddress().getHostAddress())) {

               // All checks passed; proceed...
           }
       }
   }
   ```

6. **Generate service session key `K_c,s`** and build TGS-REP:

   ```java
   SecretKey sessionKeyClient_Server = KeyMethods.generateSecretKey();
   KeyMethods.saveSecret(sessionKeyClient_Server,
                         path4KeySaving, "Client", "Server");

   UTicket userResponse = new UTicket();

   // responseToClient
   userResponse.generateResponse4User(
       "Server",                          // ID_v
       now.toString(),                    // TS4
       lifetime.toString(),               // lifetime
       KeyMethods.convertAnyKey2String(sessionKeyClient_Server) // K_c,s
   );

   // serviceTicket
   Timestamp secondLifetime = new Timestamp(
       now.getTime() + TimeMethods.getMillis(5, 0)
   );

   userResponse.generateTicket(
       "serviceTicket",
       tgt.getFirstId(),                  // ID_c
       userService.getFirstId(),          // ID_v (service ID)
       now.toString(),                    // TS4
       tgt.getAddressIP(),                // AD_c
       secondLifetime.toString(),         // lifetime
       KeyMethods.convertAnyKey2String(sessionKeyClient_Server) // K_c,s
   );
   ```

7. **Encrypt tickets for client and server**:

   ```java
   SecretKey secretTGS_Server =
       KeyMethods.recoverSecret(path4KeyRetrieving, "TGS", "Server");

   // Encrypt responseToClient with K_c,tgs
   userResponse.encryptTicket(sessionKeyTGS_Client, "responseToClient");

   // Encrypt serviceTicket with TGS–Server key
   userResponse.encryptTicket(secretTGS_Server, "serviceTicket");

   // And also encrypt serviceTicket with K_c,tgs (demo choice)
   userResponse.encryptTicket(sessionKeyTGS_Client, "serviceTicket");
   ```

   Conceptually:

    - `responseToClient` → for the client (`K_c,tgs`).
    - `serviceTicket`   → for the server (`K_tgs,s`), but in this demo it is
      also encrypted again with `K_c,tgs` so the client can inspect it.

8. **Send TGS-REP**:

   ```java
   return Messenger.ticketResponder(socket, userResponse);
   ```

If any check fails, TGS responds with a boolean `false` via
`Messenger.booleanResponder`.

### 3.3 Client processes TGS-REP

Back in `Client.Controller`:

```java
if (responseFromTGS.decryptTicket(sessionKeyClientTGS, "responseToClient")) { ... }
if (responseFromTGS.decryptTicket(sessionKeyClientTGS, "serviceTicket")) { ... }

Ticket responseTGS = responseFromTGS.searchTicket("responseToClient");
SecretKey sessionKeyClientServer =
    KeyMethods.convertString2Key(responseTGS.getKey());

String serverName = responseTGS.getFirstId(); // "Server"
KeyMethods.saveSecret(sessionKeyClientServer,
                      path4SecretKeyComms, whoAmI, serverName);
```

Client:

1. Decrypts both `responseToClient` and `serviceTicket` using `K_c,tgs`.
2. Extracts `K_c,s` from `responseToClient.key`.
3. Saves `K_c,s` as `Symmetric-Client-Server.key`.
4. Notes the server name in `responseToClient.firstId` (e.g. `"Server"`).

The client is now ready to contact the Server with a service ticket.

---

## 4. Step 3 – AP-REQ / AP-REP

### 4.1 Client → Server: AP-REQ

From `Client.Controller`:

```java
System.out.println("Solicitud al servidor");

UTicket responseFromServer =
    RequestAccess.askForService(
        responseFromTGS,                // contains serviceTicket
        whoAmI,                         // userID
        Timestamp.from(Instant.now()).toString(),
        sessionKeyClientServer,         // K_c,s
        addressIP_Self,                 // client IP
        addressIP_Server,
        connectionPort_Server
    );
```

Implementation (`RequestAccess.askForService`):

```java
public static UTicket askForService(
        UTicket ticketFromTGS,
        String userID,
        String timeStamp,
        SecretKey secretKey,            // K_c,s
        String addressIP_Self,
        String addressIP_Server,
        int connectionPort_Server) {

    UTicket askForService = new UTicket();

    // Include the service ticket from TGS
    askForService.addTicket(
        ticketFromTGS.searchTicket("serviceTicket")
    );

    // Add authenticator (auth)
    askForService.addAuthenticator(userID, addressIP_Self, timeStamp);

    if(askForService.encryptTicket(secretKey, "auth"))
        System.out.println("Ticket auth encriptado exitosamente con llave de sesión Client - Server.");
    else {
        System.out.println("Ha ocurrido un error al encriptar el ticket auth.");
        System.exit(-1);
    }

    return Messenger.ticketSender(addressIP_Server, connectionPort_Server, askForService);
}
```

AP-REQ payload:

- `serviceTicket` (encrypted for the server, and also with `K_c,s` in this demo).
- `auth` ticket encrypted with `K_c,s`, containing:
    - client ID,
    - client IP,
    - current timestamp.

### 4.2 Server processes AP-REQ

Entry point: `Controllers.Kerberos.Server.Controller`:

```java
do {
    ProcessRequest.processUserRequest(
        Messenger.requestAccepter(serverSocket),
        path4SecretKeyRetrieving,
        addressIP_Self
    );
    System.out.println("Respuesta enviada al cliente.");
} while (!serverSocket.isClosed());
```

Logic: `Controllers.Kerberos.Server.ProcessRequest`:

1. **Receive AP-REQ**:

   ```java
   UTicket userRequest = Messenger.ticketAccepter(socket);
   ```

2. **Recover Server–TGS key** and decrypt service ticket:

   ```java
   SecretKey secretKeyServer_TGS =
       KeyMethods.recoverSecret(path4KeyRetrieving, "Server", "TGS");

   userRequest.decryptTicket(secretKeyServer_TGS, "serviceTicket");
   Ticket serviceTicket = userRequest.searchTicket("serviceTicket");
   ```

3. **Check lifetime** of service ticket:

   ```java
   Timestamp now           = TimeMethods.timeSignature();
   Timestamp ticketLifetime = TimeMethods.string2TimeStamp(serviceTicket.getLifetime());

   if (now.compareTo(ticketLifetime) < 0) {
       // ok
   } else {
       System.out.println("El tiempo de vida del ticket ha expirado. Es necesario conseguir un nuevo ticket.");
       System.exit(1);
   }
   ```

4. **Recover `K_c,s`** from service ticket and decrypt authenticator:

   ```java
   SecretKey sessionKeyClientServer =
       KeyMethods.convertString2Key(serviceTicket.getKey());

   userRequest.decryptTicket(sessionKeyClientServer, "auth");
   Ticket userAuth = userRequest.searchTicket("auth");
   ```

5. **Validate client identity and IP**:

   ```java
   if (serviceTicket.getFirstId().equals(userAuth.getFirstId())) {
       if (serviceTicket.getSecondId().equals("Server") &&
           userAuth.getAddressIP().equals("localhost") // or socket IP in real deployment
       ) {
           approveSession(socket, sessionKeyClientServer, serviceIPAddress);
       }
   }

   // If any check fails:
   boolean flag;
   do flag = Messenger.booleanResponder(socket, false); while (!flag);
   ```

   The server ensures:

    - The same client ID appears in `serviceTicket` and `auth`.
    - The serviceTicket is indeed addressed to `"Server"`.
    - The client’s IP in the authenticator matches the expected address.

6. **Return AP-REP if approved**

   Helper method `approveSession(...)`:

   ```java
   public static void approveSession(
           Socket socket,
           SecretKey sessionKeyClientServer,
           String serviceIPAddress) {

       UTicket approved = new UTicket();
       approved.addAuthenticator(
           "ServiceAuth", serviceIPAddress,
           Timestamp.from(Instant.now()).toString()
       );

       if (approved.encryptTicket(sessionKeyClientServer, "auth"))
           System.out.println("Ticket auth encriptado correctamente con llave de sesión Servidor-Cliente");
       else {
           System.out.println("Ha ocurrido un error al encriptar el ticket auth.");
           System.exit(-1);
       }

       boolean flag;
       do flag = Messenger.ticketResponder(socket, approved); while (!flag);
       System.exit(0);
   }
   ```

   AP-REP payload:

    - A `UTicket` with a single `auth` ticket:
        - `firstId`   → `"ServiceAuth"`
        - `addressIP` → service IP
        - `timeStamp` → current time
        - encrypted with `K_c,s`.

### 4.3 Client processes AP-REP

Back in `Client.Controller`:

```java
if (responseFromServer.decryptTicket(sessionKeyClientServer, "auth"))
    System.out.println("El ticket auth enviado por el Server ha sido desencriptado exitosamente.");
else {
    System.out.println("Ha ocurrido un error al desencriptar el ticket auth enviado por el Server.");
    System.exit(-1);
}
responseFromServer.printTicket(responseFromServer);
System.out.println("Termina solicitud del servidor.");
```

Client:

- Decrypts the `auth` ticket using `K_c,s`.
- Reads the server’s “service authenticator” and timestamps from the console.

At this point, mutual authentication (in the simplified sense of this demo) has completed.

---

## 5. Simplifications versus “real” Kerberos

This implementation is intentionally educational and omits many production features:

- **No password-based client authentication**  
  There is no `K_c` derived from a user password. Instead, long-term symmetric
  keys (`K_as,c`, `K_as,tgs`, `K_tgs,s`) are pre-distributed by the Distributor
  phase and stored in SecretVault.

- **No pre-authentication**  
  The AS does not require a proof of knowledge of a secret before issuing a TGT.

- **No replay cache**  
  Replay protection is limited to lifetime checks and IP binding:
    - TGT and service tickets include lifetimes.
    - Authenticators include timestamps and IP.
    - There is **no** cache of previously seen authenticators.

- **Crypto choices for simplicity**
    - RSA for key exchange (default `Cipher.getInstance("RSA")`).
    - DES for symmetric encryption (`Cipher.getInstance("DES")`).
    - No mode/IV management is exposed (uses JCE defaults).

- **Single realm, single TGS, single server**  
  The model assumes one AS, one TGS, one application server. No cross-realm,
  no multiple services.

- **Visibility for learning**
    - The client can decrypt and print tickets (including TGT and serviceTicket)
      if configured that way, even though in real Kerberos those would remain
      opaque to the client.
    - Console output is verbose to show exactly what is happening at each step.

Despite these simplifications, the **shape of the protocol** closely mirrors
Kerberos:

- A first round-trip to obtain a TGT and a session key for TGS.
- A second round-trip to obtain a service ticket and a session key for the
  final server.
- A third round-trip to prove possession of the service ticket and the session
  key to the server, and to receive a server authenticator in return.

The code is structured so that each of these steps is easy to follow, inspect
and modify for experimentation.
