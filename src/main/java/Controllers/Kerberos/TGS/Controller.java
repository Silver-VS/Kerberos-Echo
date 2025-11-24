package Controllers.Kerberos.TGS;

import Model.Messenger;

import java.net.ServerSocket;

/**
 * Network service entry point for the Ticket Granting Server (TGS).
 * <p>
 * This controller is part of the Kerberos phase and is responsible for
 * handling TGS-REQ messages from clients that already possess a valid
 * Ticket-Granting Ticket (TGT). It:
 *
 * <ul>
 *   <li>Opens a {@link ServerSocket} on a fixed port (default {@code 1202}).</li>
 *   <li>Accepts incoming connections from clients.</li>
 *   <li>Delegates each request to
 *       {@link ProcessRequest#processUserRequest(java.net.Socket, String, String)}.</li>
 *   <li>Prints console logs for debugging / demonstration purposes.</li>
 * </ul>
 *
 * The TGS validates the client’s TGT and authenticator using the symmetric
 * key shared with the AS (K_tgs,as) and issues:
 *
 * <ul>
 *   <li>A service ticket for the requested server, and</li>
 *   <li>A session key K_c,s that the client will use with that server.</li>
 * </ul>
 *
 * Paths and ports are hardcoded for clarity in the demo. In a production
 * system, these would be externalized.
 *
 * @author Silver-VS
 */
public class Controller {

    /**
     * Starts the Ticket Granting Server (TGS) network loop.
     * <p>
     * Steps:
     * <ol>
     *   <li>Define:
     *       <ul>
     *         <li>{@code receivingPort} – TCP port to listen on
     *             (default {@code 1202}).</li>
     *         <li>{@code projectPath} – base path to the project.</li>
     *         <li>{@code path4SecretKeyRetrieving} – points to
     *             {@code Security/SecretVault/Connection/}, where symmetric
     *             keys shared with AS, Client, and Server are stored.</li>
     *         <li>{@code path4SecretKeySaving} – points to
     *             {@code Security/SecretVault/Generated/}, used here for
     *             storing newly generated session keys if needed.</li>
     *       </ul>
     *   </li>
     *   <li>Initialize a {@link ServerSocket} using
     *       {@link Messenger#serverSocketInitializer(int)}.</li>
     *   <li>If initialization fails, log an error and terminate the process.</li>
     *   <li>Enter a loop that:
     *       <ul>
     *         <li>Waits for incoming client connections
     *             ({@link Messenger#requestAccepter(ServerSocket)}).</li>
     *         <li>For each connection, calls
     *             {@link ProcessRequest#processUserRequest(java.net.Socket, String, String)}
     *             to handle the TGS-REQ.</li>
     *         <li>Logs whether a response was successfully sent or if an error
     *             occurred.</li>
     *       </ul>
     *   </li>
     * </ol>
     * The loop exits only when the underlying {@code ServerSocket} is closed.
     *
     * @param args not used
     */
    public static void main(String[] args) {

        int receivingPort = 1202;
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4SecretKeyRetrieving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";
        String path4SecretKeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        ServerSocket serverSocket = Messenger.serverSocketInitializer(receivingPort);

        if (serverSocket == null) {
            System.out.println("No se ha podido iniciar el Servidor.");
            System.exit(-1);
        }

        System.out.println("TGS iniciado.");

        do {
            System.out.println("En espera de petici\u00F3n...");
            if (
                    ProcessRequest.processUserRequest(
                            Messenger.requestAccepter(serverSocket),
                            path4SecretKeyRetrieving, path4SecretKeySaving
                    )
            ) {
                System.out.println("Respuesta enviada del TGS al cliente.");
            } else {
                System.out.println("Ha ocurrido un error en la respuesta.");
                System.out.println("Error: ");
            }
        } while (!serverSocket.isClosed());
    }
}
