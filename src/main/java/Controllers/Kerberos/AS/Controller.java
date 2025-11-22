package Controllers.Kerberos.AS;

import Model.Messenger;

import java.net.ServerSocket;

/**
 * Network service entry point for the Authentication Server (AS).
 * <p>
 * This controller opens a {@link ServerSocket} on a fixed port and processes
 * incoming Kerberos authentication requests from clients. For each accepted
 * connection, the request is delegated to {@link ProcessRequest}, which
 * implements the AS-side logic of the Kerberos protocol (issuing
 * Ticket-Granting Tickets, etc.).
 * <p>
 * The implementation is intentionally straightforward and uses hardcoded
 * configuration values (project path and listening port) to keep the demo
 * easy to follow. It is not intended for production use.
 *
 * @author Silver-VS
 */
public class Controller {

    /**
     * Starts the Authentication Server (AS) network service.
     * <p>
     * Steps:
     * <ol>
     *   <li>Configure the listening port (currently {@code 1121}).</li>
     *   <li>Resolve the file system paths for:
     *       <ul>
     *           <li>{@code Security/SecretVault/Generated} – generated keys for the AS.</li>
     *           <li>{@code Security/SecretVault/Connection} – keys/credentials exchanged
     *               with other principals.</li>
     *       </ul>
     *   </li>
     *   <li>Initialize a {@link ServerSocket} via
     *       {@link Messenger#serverSocketInitializer(int)}.</li>
     *   <li>Enter a loop that:
     *       <ul>
     *           <li>Waits for incoming client connections.</li>
     *           <li>Delegates the request to
     *               {@link ProcessRequest#processUserRequest(java.net.Socket, String, String)}.</li>
     *           <li>Logs whether the response was sent successfully.</li>
     *       </ul>
     *   </li>
     * </ol>
     * The loop terminates only when the underlying {@code ServerSocket} is closed.
     *
     * @param args not used
     */
    public static void main(String[] args) {

        int receivingPort = 1121;
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4SecretKeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4SecretKeyComms = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        ServerSocket serverSocket = Messenger.serverSocketInitializer(receivingPort);

        if (serverSocket == null) {
            System.out.println("No se ha podido iniciar el Servidor.");
            System.exit(-1);
        }

        System.out.println("AS iniciado.");

        do {
            System.out.println("En espera de petici\u00F3n...");
            if (
                    ProcessRequest.processUserRequest(
                            Messenger.requestAccepter(serverSocket),
                            path4SecretKeySaving, path4SecretKeyComms
                    )
            ) {
                System.out.println("Respuesta enviada del AS al cliente.");
            } else {
                System.out.println("Ha ocurrido un error en la respuesta.");
            }
        } while (!serverSocket.isClosed());
    }

}
