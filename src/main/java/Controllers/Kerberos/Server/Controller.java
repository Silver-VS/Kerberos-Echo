package Controllers.Kerberos.Server;

import Model.Messenger;

import java.net.ServerSocket;

/**
 * Network service entry point for the protected application server.
 * <p>
 * This controller belongs to the Kerberos phase of the demo. It exposes the
 * server-side endpoint that the Client ultimately contacts in order to access
 * a protected service using a Kerberos-style <strong>AP-REQ / AP-REP</strong>
 * exchange.
 * <p>
 * The class is intentionally simple:
 * it opens a {@link ServerSocket} on a fixed port and delegates each accepted
 * connection to {@link ProcessRequest}, which implements the server-side
 * authentication logic (validation of the service ticket and authenticator).
 * <p>
 * Configuration (paths and ports) is hardcoded for didactic purposes and can
 * be adapted by editing the first lines of {@link #main(String[])}.
 *
 * @author Silver-VS
 */
public class Controller {

    /**
     * Starts the Application Server network loop.
     * <p>
     * Steps:
     * <ol>
     *   <li>Define:
     *       <ul>
     *         <li>{@code projectPath} – base directory of the project (used to
     *             resolve the SecretVault paths).</li>
     *         <li>{@code addressIP_Self} – logical address/host name of this
     *             server (used by the Kerberos logic when building authenticators).</li>
     *         <li>{@code receivingPort} – TCP port where AP-REQ messages are accepted
     *             (default {@code 1203}).</li>
     *       </ul>
     *   </li>
     *   <li>Build {@code path4SecretKeyRetrieving}, pointing to
     *       {@code Security/SecretVault/Connection/}, where long-term and
     *       session keys (e.g. TGS–Server, Client–Server) are stored.</li>
     *   <li>Initialize a {@link ServerSocket} via
     *       {@link Messenger#serverSocketInitializer(int)}.</li>
     *   <li>If initialization fails, log an error and terminate the process.</li>
     *   <li>Enter a loop that:
     *       <ul>
     *         <li>Waits for incoming client connections
     *             ({@link Messenger#requestAccepter(ServerSocket)}).</li>
     *         <li>Passes each accepted {@code Socket} to
     *             {@link ProcessRequest#processUserRequest(java.net.Socket, String, String)},
     *             along with the key path and {@code addressIP_Self}.</li>
     *         <li>Logs that a response has been sent back to the client.</li>
     *       </ul>
     *   </li>
     * </ol>
     * The loop runs until the underlying {@code ServerSocket} is closed.
     *
     * @param args not used
     */
    public static void main(String[] args) {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        String addressIP_Self = "localhost";
        int receivingPort = 1203;

        String path4SecretKeyRetrieving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        ServerSocket serverSocket = Messenger.serverSocketInitializer(receivingPort);

        if (serverSocket == null) {
            System.out.println("No se ha podido iniciar el Servidor.");
            System.exit(-1);
        }

        System.out.println("Servidor iniciado.");

        do {
            System.out.println("En espera de petici\u00F3n...");

            ProcessRequest.processUserRequest(
                    Messenger.requestAccepter(serverSocket),
                    path4SecretKeyRetrieving, addressIP_Self
            );
            System.out.println("Respuesta enviada al cliente.");
        } while (!serverSocket.isClosed());
    }
}
