package Controllers.Kerberos.AS;

import Model.Messenger;
import Model.Ticket;
import Model.TimeMethods;
import Model.UTicket;
import Security.Model.Encryption;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.Socket;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * Handles client requests to the Authentication Server (AS).
 * <p>
 * This class implements the AS-REQ / AS-REP exchange:
 * <ol>
 *   <li>Receives an initial authentication request from the client, wrapped in a {@link UTicket}
 *       containing a ticket with {@code idTicket = "request"}.</li>
 *   <li>Generates a fresh session key {@code K_c,tgs} for the Client–TGS communication.</li>
 *   <li>Builds the AS-REP as a new {@link UTicket} containing:
 *       <ul>
 *         <li>{@code "responseToClient"} – a ticket readable by the client, which carries {@code K_c,tgs}.</li>
 *         <li>{@code "TGT"} – a Ticket Granting Ticket that will later be presented to the TGS.</li>
 *       </ul>
 *   </li>
 *   <li>Encrypts {@code "responseToClient"} with the long-term AS–Client key.</li>
 *   <li>Encrypts {@code "TGT"} using the AS–TGS and AS–Client keys (for demonstration purposes).</li>
 *   <li>Sends the resulting {@link UTicket} back to the client over the socket.</li>
 * </ol>
 *
 * The generated long-term and session keys are persisted using {@link KeyMethods}
 * under {@code Security/SecretVault/Generated} and {@code Security/SecretVault/Connection}.
 * <br><br>
 * @author Silver-VS
 */

public class ProcessRequest {

    /**
     * Processes an AS-REQ from the client and sends an AS-REP response.
     *
     * @param socket            accepted socket representing the client connection
     * @param path4KeySaving    path where new symmetric keys (e.g. Client–TGS) should be stored
     * @param path4KeyRetrieving path where existing long-term keys (AS–Client, AS–TGS) are stored
     * @return {@code true} if the response was sent successfully, {@code false} otherwise
     */
    public static boolean processUserRequest(Socket socket, String path4KeySaving, String path4KeyRetrieving) {
        try {
            UTicket userRequest = Messenger.ticketAccepter(socket);
            if (userRequest == null) {
                System.out.println("Ha ocurrido un error");
                System.exit(-1);
            }
            Ticket ticket = userRequest.searchTicket("request");
            UTicket userResponse = new UTicket();

            System.out.println("Ticket recibido");
            userResponse.printTicket(userRequest);
            System.out.println("Final de ticket recibido");

            SecretKey sessionKeyClientTGS = KeyMethods.generateSecretKey();
            KeyMethods.saveSecret(sessionKeyClientTGS, path4KeySaving, "Client", "TGS");

            Timestamp timestamp = Timestamp.from(Instant.now());
            Timestamp lifetime = new Timestamp(timestamp.getTime() + TimeMethods.getMillis(5,0));

            userResponse.generateResponse4User( // Name of ticket: responseToClient
                    "TGS - Victor", // ID TGS
                    timestamp.toString(), // TS 2
                    lifetime.toString(), // Tiempo de vida 2
                    KeyMethods.convertAnyKey2String(sessionKeyClientTGS)); // K c-tgs

            userResponse.generateTicket(
                    "TGT", // Ticket TGS
                    ticket.getFirstId(), // ID c
                    "TGS - Victor", // ID tgs
                    timestamp.toString(), // TS 2
                    socket.getInetAddress().getHostAddress(), //AD c
                    lifetime.toString(), // Tiempo de vida 2
                    KeyMethods.convertAnyKey2String(sessionKeyClientTGS)); // K c-tgs

            SecretKey secretAS_Client = KeyMethods.recoverSecret(path4KeyRetrieving, "AS", "Client");
            SecretKey secretAS_TGS = KeyMethods.recoverSecret(path4KeyRetrieving, "AS", "TGS");

            if (userResponse.encryptTicket(secretAS_Client, "responseToClient"))
                System.out.println("El ticket responseToClient ha sido encriptado con la llave AS-Client exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al encriptar el ticket responseToClient");
                System.exit(-1);
            }
            if (userResponse.encryptTicket(secretAS_TGS, "TGT"))
                System.out.println("Ticket TGT ha sido encriptado exitosamente con la llave secrete AS-TGS.");
            else {
                System.out.println("Ha ocurrido un error al encriptar el ticket TGT");
                System.exit(-1);
            }
            if (userResponse.encryptTicket(secretAS_Client, "TGT"))
                System.out.println("Ticket TGT ha sido encriptado exitosamente con la llave secrete AS-Client.");
            else {
                System.out.println("Ha ocurrido un error al encriptar el ticket TGT");
                System.exit(-1);
            }

            return Messenger.ticketResponder(socket, userResponse);

        } catch (Exception e) {

            e.printStackTrace();
            return false;
        }
    }

}
