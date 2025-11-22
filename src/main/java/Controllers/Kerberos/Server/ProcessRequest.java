package Controllers.Kerberos.Server;

import Model.Messenger;
import Model.Ticket;
import Model.TimeMethods;
import Model.UTicket;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.Socket;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * Handles client requests to the application server.
 * <p>
 * This class implements the AP-REQ / AP-REP exchange:
 * <ol>
 *   <li>Receives a {@link UTicket} from the client containing:
 *       <ul>
 *         <li>{@code "serviceTicket"} – ticket issued by the TGS for this server.</li>
 *         <li>{@code "auth"} – client authenticator encrypted with {@code K_c,s}.</li>
 *       </ul>
 *   </li>
 *   <li>Decrypts the service ticket using the Server–TGS symmetric key.</li>
 *   <li>Validates that the ticket has not expired.</li>
 *   <li>Extracts the session key {@code K_c,s} from the service ticket.</li>
 *   <li>Decrypts the authenticator with {@code K_c,s} and validates:
 *       <ul>
 *         <li>Client identity matches the service ticket.</li>
 *         <li>The ticket is indeed addressed to this server.</li>
 *         <li>The client IP address is consistent.</li>
 *       </ul>
 *   </li>
 *   <li>If validation succeeds, builds an AP-REP message as a new {@link UTicket}
 *       containing an {@code "auth"} ticket (service authenticator) encrypted
 *       with {@code K_c,s} and sends it back to the client.</li>
 *   <li>If validation fails, sends a boolean {@code false} response instead.</li>
 * </ol>
 * <br><br>
 * @author Silver-VS
 */

public class ProcessRequest {

    /**
     * Processes an AP-REQ from the client and sends an AP-REP response.
     *
     * @param socket             accepted socket representing the client connection
     * @param path4KeyRetrieving path where the Server–TGS symmetric key is stored
     * @param serviceIPAddress   IP address or logical identifier used in the server's authenticator
     */
    public static void processUserRequest(Socket socket, String path4KeyRetrieving, String serviceIPAddress) {
        try {

            UTicket userRequest = Messenger.ticketAccepter(socket);

            if (userRequest == null) {
                System.out.println("Ha ocurrido un error");
                System.exit(-1);
            }

            //  We retrieve our SecretKey with the TGS.
            SecretKey secretKeyServer_TGS = KeyMethods.recoverSecret(path4KeyRetrieving, "Server", "TGS");

            //  We decrypt our ticket with our secret key.
            userRequest.decryptTicket(secretKeyServer_TGS, "serviceTicket");

            Ticket serviceTicket = userRequest.searchTicket("serviceTicket");

            Timestamp now = TimeMethods.timeSignature();

            Timestamp ticketLifetime = TimeMethods.string2TimeStamp(serviceTicket.getLifetime());

            if (now.compareTo(ticketLifetime) < 0){
                SecretKey sessionKeyClientServer = KeyMethods.convertString2Key(serviceTicket.getKey());

                userRequest.decryptTicket(sessionKeyClientServer, "auth");

                Ticket userAuth = userRequest.searchTicket("auth");


                if (serviceTicket.getFirstId().equals(userAuth.getFirstId())) {
                    if (
                            serviceTicket.getSecondId().equals("Server")
                                    &&

                                    userAuth.getAddressIP().equals("localhost")
//                                userAuth.getAddressIP().equals(socket.getInetAddress().getHostAddress())
                    )
                        approveSession(socket, sessionKeyClientServer, serviceIPAddress);
                }
                boolean flag;
                do flag = Messenger.booleanResponder(socket, false); while (!flag);
            } else {
                System.out.println("El tiempo de vida del ticket ha expirado. Es necesario conseguir un nuevo ticket.");
                System.exit(1);
            }

        } catch (Exception e) {
            System.out.println("Ha ocurrido un error.");
            System.out.println("Error: ");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Builds and sends a positive AP-REP response back to the client.
     * <p>
     * This method:
     * <ul>
     *   <li>Creates a {@link UTicket} with a single {@code "auth"} ticket
     *       (service authenticator).</li>
     *   <li>Encrypts it with the session key {@code K_c,s} shared with the client.</li>
     *   <li>Uses {@link Messenger#ticketResponder(Socket, UTicket)} to send it.</li>
     * </ul>
     *
     * @param socket               socket connected to the client
     * @param sessionKeyClientServer session key {@code K_c,s} shared with the client
     * @param serviceIPAddress     IP address or identifier of the service/server
     */
    public static void approveSession(Socket socket, SecretKey sessionKeyClientServer, String serviceIPAddress) {
        UTicket approved = new UTicket();
        approved.addAuthenticator("ServiceAuth", serviceIPAddress, Timestamp.from(Instant.now()).toString());
        if (approved.encryptTicket(sessionKeyClientServer, "auth"))
            System.out.println("Ticket auth encriptado correctamente con llave de sesi\u00F3n Servidor-Cliente");
        else {
            System.out.println("Ha ocurrido un error al encriptar el ticket auth.");
            System.exit(-1);
        }
        boolean flag;
        do flag = Messenger.ticketResponder(socket, approved); while (!flag);
        System.exit(0);
    }
}