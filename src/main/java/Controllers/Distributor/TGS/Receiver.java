package Controllers.Distributor.TGS;

import Model.KeyDistributor;

import java.net.ServerSocket;
/**
 * Receiver-side bootstrap for establishing symmetric keys with the TGS.
 * <p>
 * This class opens a {@link ServerSocket} and waits for a peer (for example,
 * the Server) to connect, send its public key and receive a freshly generated
 * symmetric key.
 *
 * Concretely, this demo implementation:
 *
 * <ul>
 *   <li>Listens on a fixed port (e.g. {@code 5501}).</li>
 *   <li>Accepts the peer's public key and stores it as
 *       {@code public<Peer>Received.key} in
 *       {@code Security/SecretVault/Connection/}.</li>
 *   <li>Generates a new symmetric key (DES) for TGS ↔ &lt;Peer&gt;.</li>
 *   <li>Saves it as {@code Symmetric-TGS-<Peer>.key} in
 *       {@code Security/SecretVault/Connection/}.</li>
 *   <li>Sends the symmetric key back to the peer encrypted with its public key.</li>
 * </ul>
 *
 * This class must be started <strong>before</strong> the corresponding
 * Sender on the peer side. In a true distributed deployment, it would run
 * on the TGS host only.
 *
 * @author Silver-VS
 */
public class Receiver {
    /**
     * Starts the TGS Receiver for the Distributor phase.
     * <p>
     * The main method:
     * <ol>
     *   <li>Configures the project path and key-savings directory.</li>
     *   <li>Opens a {@link ServerSocket} on the configured port.</li>
     *   <li>Invokes {@link KeyDistributor#receiver(ServerSocket, String, String, String)}
     *       to perform the key exchange with the peer (e.g. the Server).</li>
     * </ol>
     *
     * @param args not used
     * @throws Exception if network I/O or key operations fail
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        ServerSocket serverSocket = new ServerSocket(5501);

        String whoAmI = "TGS";
        String senderName;
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        senderName = "Server";
        KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving);

    }
}
