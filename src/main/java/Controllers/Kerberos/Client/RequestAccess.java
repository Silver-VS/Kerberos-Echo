package Controllers.Kerberos.Client;

import Model.Messenger;
import Model.UTicket;

import javax.crypto.SecretKey;

/**
 * Client-side helper for building and sending Kerberos protocol messages.
 * <p>
 * This class encapsulates the construction of the three main request types
 * the Client sends during the Kerberos phase:
 *
 * <ul>
 *   <li><strong>AS-REQ</strong> – initial request to the Authentication Server (AS)
 *       asking for a Ticket-Granting Ticket (TGT).</li>
 *   <li><strong>TGS-REQ</strong> – request to the Ticket Granting Server (TGS)
 *       asking for a service ticket.</li>
 *   <li><strong>AP-REQ</strong> – request to the Application Server, presenting
 *       the service ticket and an authenticator.</li>
 * </ul>
 *
 * Each method builds a {@link UTicket} with the appropriate set of tickets
 * and authenticators, applies the necessary encryption, and hands it to
 * {@link Messenger#ticketSender(String, int, UTicket)} to send it over
 * the network.
 *
 * This is a purely static utility class; it holds no state.
 *
 * @author Silver-VS
 */
public class RequestAccess {

    /**
     * Builds and sends the initial AS-REQ to the Authentication Server.
     * <p>
     * Steps:
     * <ol>
     *   <li>Create a new {@link UTicket}.</li>
     *   <li>Call {@link UTicket#generateRequest(String, String, String)} to add
     *       the client’s request ticket:
     *       <ul>
     *         <li>{@code firstId}  = {@code userID}</li>
     *         <li>{@code secondId} = {@code serviceID}</li>
     *         <li>{@code lifetime} = {@code requestedLifetime}</li>
     *       </ul>
     *   </li>
     *   <li>Send the ticket to the AS using
     *       {@link Messenger#ticketSender(String, int, UTicket)}.</li>
     * </ol>
     *
     * In Kerberos terms, this corresponds to the AS-REQ message.
     *
     * @param userID            logical identifier of the client (ID_c)
     * @param serviceID         identifier of the requested service or TGS (ID_tgs)
     * @param requestedLifetime requested lifetime for the ticket, as a String
     *                          (typically a timestamp/interval representation)
     * @param addressIP_AS      IP/hostname where the Authentication Server listens
     * @param connectionPort_AS TCP port where the AS receives AS-REQ messages
     * @return the {@link UTicket} returned by the AS (AS-REP), or {@code null}
     *         if the send/receive fails internally
     */
    public static UTicket startAuth(String userID, String serviceID, String requestedLifetime,
                                    String addressIP_AS, int connectionPort_AS) {

        UTicket serviceRequest = new UTicket();
        serviceRequest.generateRequest(userID, serviceID, requestedLifetime);
        return Messenger.ticketSender(addressIP_AS, connectionPort_AS, serviceRequest);
    }

    /**
     * Builds and sends the TGS-REQ to the Ticket Granting Server (TGS).
     * <p>
     * Expected inputs:
     * <ul>
     *   <li>{@code ticketFromAS} – the AS-REP previously returned by {@link #startAuth},
     *       containing the TGT and response to the client.</li>
     *   <li>{@code sessionKeyClientTGS} – session key K_c,tgs recovered from the
     *       AS response and stored under the Client’s SecretVault.</li>
     * </ul>
     * <p>
     * Steps:
     * <ol>
     *   <li>Create a new {@link UTicket}.</li>
     *   <li>Copy the TGT from {@code ticketFromAS}:
     *       {@code ticketFromAS.searchTicket("TGT")}.</li>
     *   <li>Add a {@code request4TGS} ticket indicating the target service
     *       via {@link UTicket#request4TGS(String)}.</li>
     *   <li>Add an {@code auth} ticket (authenticator) with
     *       {@code userID}, {@code addressIP_Self} and {@code timeStamp} via
     *       {@link UTicket#addAuthenticator(String, String, String)}.</li>
     *   <li>Encrypt the authenticator with {@code sessionKeyClientTGS}
     *       ({@link UTicket#encryptTicket(SecretKey, String)}).</li>
     *   <li>Send the bundle to the TGS using
     *       {@link Messenger#ticketSender(String, int, UTicket)}.</li>
     * </ol>
     *
     * In Kerberos terms, this corresponds to the TGS-REQ message.
     *
     * @param ticketFromAS         AS-REP carrying the TGT and responseToClient
     * @param serviceID            identifier of the final service the client wants (ID_v)
     * @param sessionKeyClientTGS  session key K_c,tgs shared between Client and TGS
     * @param requestedLifetime    requested lifetime for the service ticket (not
     *                             currently used in the method body, kept for API symmetry)
     * @param userID               logical identifier of the client (ID_c)
     * @param timeStamp            timestamp to include in the authenticator (TS)
     * @param addressIP_Self       client IP/address to include in the authenticator (AD_c)
     * @param addressIP_TGS        IP/hostname where the TGS listens
     * @param connectionPort_TGS   TCP port where the TGS receives TGS-REQ messages
     * @return the {@link UTicket} returned by the TGS (TGS-REP), or {@code null}
     *         if there is a network or processing error
     */
    public static UTicket followTGS(UTicket ticketFromAS, String serviceID, SecretKey sessionKeyClientTGS,
                                    String requestedLifetime, String userID, String timeStamp,
                                    String addressIP_Self, String addressIP_TGS, int connectionPort_TGS) {

        UTicket followUpTicketTGS = new UTicket();
        followUpTicketTGS.addTicket(ticketFromAS.searchTicket("TGT"));
        followUpTicketTGS.request4TGS(serviceID);
        followUpTicketTGS.addAuthenticator(userID, addressIP_Self, timeStamp);
        System.out.println("Tickets a enviar:\n");
        followUpTicketTGS.printTicket(followUpTicketTGS);

        if (followUpTicketTGS.encryptTicket(sessionKeyClientTGS, "auth"))
            System.out.println("\nTicket auth encriptado exitosamente con llave de sesi\u00F3n Client - TGS");
        else {
            System.out.println("\nHa ocurrido un error al encriptar el ticket auth.");
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

    /**
     * Builds and sends the AP-REQ to the protected Application Server.
     * <p>
     * Expected inputs:
     * <ul>
     *   <li>{@code ticketFromTGS} – the TGS-REP previously returned by
     *       {@link #followTGS}, containing the service ticket.</li>
     *   <li>{@code secretKey} – session key K_c,s shared between Client and Server.</li>
     * </ul>
     * <p>
     * Steps:
     * <ol>
     *   <li>Create a new {@link UTicket}.</li>
     *   <li>Copy the {@code serviceTicket} from {@code ticketFromTGS}.</li>
     *   <li>Add an {@code auth} ticket with {@code userID}, {@code addressIP_Self}
     *       and {@code timeStamp}.</li>
     *   <li>Encrypt the authenticator with K_c,s
     *       via {@link UTicket#encryptTicket(SecretKey, String)}.</li>
     *   <li>Send the bundle to the Server using
     *       {@link Messenger#ticketSender(String, int, UTicket)}.</li>
     * </ol>
     *
     * In Kerberos terms, this corresponds to the AP-REQ message (the client
     * presenting its service ticket to the application server).
     *
     * @param ticketFromTGS       TGS-REP carrying the service ticket
     * @param userID              logical identifier of the client (ID_c)
     * @param timeStamp           timestamp to include in the authenticator (TS)
     * @param secretKey           session key K_c,s shared between Client and Server
     * @param addressIP_Self      client IP/address to include in the authenticator (AD_c)
     * @param addressIP_Server    IP/hostname where the application Server listens
     * @param connectionPort_Server TCP port where the Server receives AP-REQ messages
     * @return the {@link UTicket} returned by the Server (AP-REP), or {@code null}
     *         if the send/receive fails
     */
    public static UTicket askForService(UTicket ticketFromTGS, String userID, String timeStamp,
                                        SecretKey secretKey, String addressIP_Self,
                                        String addressIP_Server, int connectionPort_Server) {

        UTicket askForService = new UTicket();
        askForService.addTicket(ticketFromTGS.searchTicket("serviceTicket"));
        askForService.addAuthenticator(userID, addressIP_Self, timeStamp);

        if(askForService.encryptTicket(secretKey, "auth"))
            System.out.println("Ticket auth encriptado exitosamente con llave de sesi\u00F3n Client - Server.");
        else {
            System.out.println("Ha ocurrido un error al encriptar el ticket auth.");
            System.exit(-1);
        }
        return Messenger.ticketSender(addressIP_Server, connectionPort_Server, askForService);

    }
}
