package Controllers.Distributor.AS;

import Model.KeyDistributor;

import java.net.ServerSocket;

/**
 * Receiver-side bootstrap for establishing symmetric keys with the
 * Authentication Server (AS).
 * <p>
 * This class is part of the <em>Distributor phase</em>. It runs on the AS
 * machine and waits for peers (Client and TGS in this demo) to connect,
 * send their public keys, and receive a freshly generated symmetric key.
 *
 * <p>Concretely, this implementation:</p>
 * <ul>
 *   <li>Opens a single {@link ServerSocket} on a fixed port (default {@code 5521}).</li>
 *   <li>Sequentially serves:
 *     <ol>
 *       <li>A connection from the Client, establishing K_as,c.</li>
 *       <li>A connection from the TGS, establishing K_as,tgs.</li>
 *     </ol>
 *   </li>
 *   <li>For each peer, delegates to
 *       {@link KeyDistributor#receiver(ServerSocket, String, String, String)} to:
 *       <ul>
 *         <li>Accept the peer's public key and store it as
 *             {@code public<Peer>Received.key} under
 *             {@code Security/SecretVault/Connection/}.</li>
 *         <li>Generate a new symmetric key for AS ↔ &lt;Peer&gt;.</li>
 *         <li>Save it as {@code Symmetric-AS-<Peer>.key} in
 *             {@code Security/SecretVault/Connection/}.</li>
 *         <li>Send the symmetric key back encrypted with the peer's public key.</li>
 *       </ul>
 *   </li>
 * </ul>
 *
 * <p><strong>Important:</strong> This Receiver must be started
 * <em>before</em> the corresponding Distributor Senders on the Client and
 * TGS, otherwise their connection attempts will fail.</p>
 *
 * <p>For simplicity, paths and ports are hardcoded. In a multi-node setup
 * this class would still run on the AS host only, but {@code projectPath}
 * and the listening port should be adjusted accordingly.</p>
 *
 * @author Silver-VS
 */
public class Receiver {

    /**
     * Starts the AS Distributor Receiver and sequentially establishes
     * symmetric keys with the Client and the TGS.
     * <p>
     * Steps:
     * <ol>
     *   <li>Open a {@link ServerSocket} on port {@code 5521}.</li>
     *   <li>Resolve {@code path4KeySaving} to
     *       {@code Security/SecretVault/Connection/}.</li>
     *   <li>Call {@link KeyDistributor#receiver(ServerSocket, String, String, String)}
     *       once for the Client (establishing K_as,c).</li>
     *   <li>Call {@link KeyDistributor#receiver(ServerSocket, String, String, String)}
     *       again for the TGS (establishing K_as,tgs).</li>
     *   <li>Log an error if any of the exchanges fail.</li>
     * </ol>
     * The same {@link ServerSocket} instance is reused for both peers; it
     * simply accepts connections sequentially.
     *
     * @param args not used
     * @throws Exception if network I/O or key operations fail
     */
    public static void main(String[] args) throws Exception {

        ServerSocket serverSocket = new ServerSocket(5521);
        String whoAmI = "AS";
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String senderName;
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        senderName = "Client";
        if (!KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving))
            System.out.println("Ha ocurrido un error");
        senderName = "TGS";
        if (!KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving))
            System.out.println("Ha ocurrido un error");
    }
}
