package Controllers.Kerberos.Client;

import Model.Ticket;
import Model.TimeMethods;
import Model.UTicket;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * Kerberos client controller and demo entry point.
 * <p>
 * This class runs the full Kerberos authentication flow from the client's
 * perspective in three stages:
 * <ol>
 *   <li><b>AS-REQ / AS-REP</b>: request a Ticket-Granting Ticket (TGT) from the Authentication Server (AS).</li>
 *   <li><b>TGS-REQ / TGS-REP</b>: use the TGT to request a service ticket from the Ticket-Granting Server (TGS).</li>
 *   <li><b>AP-REQ / AP-REP</b>: use the service ticket to authenticate to the application server (Server).</li>
 * </ol>
 * For simplicity, the IP addresses, ports and file system paths are currently
 * hardcoded, and all three servers (AS, TGS, Server) are assumed to be
 * reachable on {@code localhost} with predefined ports.
 *
 * <p>High-level flow:</p>
 * <ol>
 *   <li>Load the long-term symmetric key shared between Client and AS from
 *       {@code Security/SecretVault/Connection}.</li>
 *   <li>Build and send an AS request ticket using
 *       {@link RequestAccess#startAuth(String, String, String, String, int)}.</li>
 *   <li>Decrypt the AS response (AS-REP) to obtain:
 *       <ul>
 *         <li>The TGT intended for the TGS.</li>
 *         <li>The session key {@code K_c,tgs} for communication with the TGS.</li>
 *       </ul>
 *   </li>
 *   <li>Save {@code K_c,tgs} and send a TGS request ticket using
 *       {@link RequestAccess#followTGS(UTicket, String, javax.crypto.SecretKey, String, String, String, String, String, int)}.</li>
 *   <li>Decrypt the TGS response (TGS-REP) to obtain:
 *       <ul>
 *         <li>The service ticket intended for the Server.</li>
 *         <li>The session key {@code K_c,s} for communication with the Server.</li>
 *       </ul>
 *   </li>
 *   <li>Save {@code K_c,s} and send a service request (AP-REQ) using
 *       {@link RequestAccess#askForService(UTicket, String, String, javax.crypto.SecretKey, String, String, int)}.</li>
 *   <li>Decrypt the server's response (AP-REP) using {@code K_c,s} and print
 *       the result.</li>
 * </ol>
 *
 * This implementation is intentionally verbose and prints each step to the
 * console to support demonstration and learning.
 * <br><br>
 * @author Silver-VS
 */

public class Controller {
    public static void main(String[] args) {
        //  Main project directory
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        //  Client info
        String whoAmI = "Client";
        String addressIP_Self = "localhost";

        //  AS info
        String addressIP_AS = "localhost";
        int connectionPort_AS = 1121;

        //  TGS info
        String addressIP_TGS = "localhost";
        int connectionPort_TGS = 1202;

        //  Server info
        String addressIP_Server = "localhost";
        int connectionPort_Server = 1203;

        //  Variables to use later on.
        String receiverName;
        SecretKey ClientAS;
        SecretKey sessionKeyClientTGS;
        SecretKey sessionKeyClientServer;
        //  This lifetime can be changed accordingly to the interpretation we are giving it.
        Timestamp requestedLifetime = TimeMethods.timeSignature();
        requestedLifetime.setTime(requestedLifetime.getTime() + TimeMethods.getMillis(5, 0));
        String path4SecretKeyComms = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        try { //Intenta encontrar la llave del AS con el Cliente

            ClientAS = KeyMethods.recoverSecret(path4SecretKeyComms, whoAmI, "AS");

            System.out.print("\nSolicitud al AS");
            receiverName = "AS";
            //  We send the request ticket to the AS and receive the response from the AS
            UTicket responseFromAS = RequestAccess.startAuth(whoAmI, receiverName, requestedLifetime.toString(),
                    addressIP_AS, connectionPort_AS);
            //  We decrypt the tickets with our secret key.
            if (responseFromAS.decryptTicket(ClientAS, "responseToClient"))
                System.out.println("El ticket responseToClient enviado por el AS ha sido desencriptado exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket responseToClient enviado por el AS.");
                System.exit(-1);
            }

            if (responseFromAS.decryptTicket(ClientAS, "TGT"))
                System.out.println("El ticket TGT enviado por el AS ha sido desencriptado exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket TGT enviado por el AS.");
                System.exit(-1);
            }
            //  We show in console the tickets unencrypted, but we should only be able to read the response to
            //  the client, but not TGT, as this is still encrypted with the Public key of the TGS.
            System.out.println("\nTickets decrypted: ");
            responseFromAS.printTicket(responseFromAS);
            System.out.println("Termina respuesta del AS\n");

            //  We retrieve the secret key sent by the AS for communication with the TGS.
            Ticket responseAS = responseFromAS.searchTicket("responseToClient");
            sessionKeyClientTGS = KeyMethods.convertString2Key(responseAS.getKey());
            KeyMethods.saveSecret(sessionKeyClientTGS, path4SecretKeyComms, whoAmI, "TGS");

            //We send the TGT, emitted by the AS, to the TGS, adding our authenticator and our ID.
            System.out.println("Solicitud al TGS");
            UTicket responseFromTGS =
                    RequestAccess.followTGS(
                            responseFromAS, "Server", sessionKeyClientTGS, responseAS.getLifetime(), whoAmI,
                            TimeMethods.timeSignature().toString(),
                            addressIP_Self, addressIP_TGS, connectionPort_TGS
                    );
            if (responseFromTGS == null) {
                System.out.println("Ha ocurrido un error al recibir la respuesta.");
                System.exit(-1);
            }
            //  We decrypt the tickets using the key sent by the AS for communication with the TGS.
            if (responseFromTGS.decryptTicket(sessionKeyClientTGS, "responseToClient"))
                System.out.println("El ticket responseToClient enviado por el TGS ha sido desencriptado exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket responseToClient enviado por el TGS.");
                System.exit(-1);
            }
            if (responseFromTGS.decryptTicket(sessionKeyClientTGS, "serviceTicket"))
                System.out.println("El ticket responseToClient enviado por el TGS ha sido desencriptado exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket responseToClient enviado por el TGS.");
                System.exit(-1);
            }
            //  We show in console the tickets unencrypted, but we should only be able to read the response to
            //  the client, but not serviceTicket, as this is still encrypted with the Public key of the Server.
            responseFromTGS.printTicket(responseFromTGS);
            System.out.println("\nTermina respuesta del TGS");

            //  We retrieve the secret key sent by the TGS for communication with the Server.
            Ticket responseTGS = responseFromTGS.searchTicket("responseToClient");
            sessionKeyClientServer = KeyMethods.convertString2Key(responseTGS.getKey());
            String serverName = responseTGS.getFirstId();
            KeyMethods.saveSecret(sessionKeyClientServer, path4SecretKeyComms, whoAmI, serverName);

            //  We sent the ServiceTicket, emitted by the TGS, to the Server, adding our auth.
            System.out.println("Solicitud al servidor");
            UTicket responseFromServer =
                    RequestAccess.askForService(
                            responseFromTGS, whoAmI, Timestamp.from(Instant.now()).toString(),
                            sessionKeyClientServer, addressIP_Self, addressIP_Server, connectionPort_Server
                    );

            if (responseFromServer == null) {
                System.out.println("Ha ocurrido un error al recibir la respuesta del servidor");
                System.exit(-1);
            }

            //  We decrypt the ticket using the key sent by the TGS for communication with the Server.
            if (responseFromServer.decryptTicket(sessionKeyClientServer, "auth"))
                System.out.println("El ticket auth enviado por el Server ha sido desencriptado exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket auth enviado por el Server.");
                System.exit(-1);
            }
            responseFromServer.printTicket(responseFromServer);
            System.out.println("Termina solicitud del servidor.");

        } catch (Exception e) {
            System.out.println("Ha ocurrido un error.");
            System.out.println("Error: ");
            e.printStackTrace();
            System.exit(-1);
        }

    }
}
