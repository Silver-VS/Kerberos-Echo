package Controllers.Distributor.TGS;

import Model.KeyDistributor;

/**
 * Sender-side bootstrap for establishing symmetric keys with the TGS.
 * <p>
 * This class represents the TGS actively connecting to a peer (for example,
 * the AS) in order to exchange public keys and receive/store a symmetric key.
 *
 * The protocol is implemented by {@link Model.KeyDistributor} and follows
 * this pattern:
 *
 * <ol>
 *   <li>TGS loads its own RSA key pair from
 *       {@code Security/SecretVault/Generated/}.</li>
 *   <li>Connects to the peer's Receiver socket (host + port).</li>
 *   <li>Sends its public key.</li>
 *   <li>Receives a symmetric key encrypted with its public key.</li>
 *   <li>Decrypts it with its private key and stores it as
 *       {@code Symmetric-TGS-<Peer>.key} in
 *       {@code Security/SecretVault/Connection/}.</li>
 * </ol>
 *
 * This class should be run <strong>after</strong> the corresponding Receiver
 * is already listening on the target host/port.
 *
 * @author Silver-VS
 */
public class Sender {
    /**
     * Initiates the Distributor key-exchange from the TGS to another principal
     * (e.g. the AS), establishing a long-term symmetric key.
     *
     * @param args not used
     * @throws Exception if network I/O or key operations fail
     */
    public static void main(String[] args) throws Exception {
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        int connectionPort = 5521;

        String whoAmI = "TGS";
        String receiverHost = "localhost";
        String receiverName = "AS";
        String path4KeyRetrieval = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        KeyDistributor.publicSenderSecretReceiver(receiverHost, connectionPort, receiverName, whoAmI,
                path4KeyRetrieval, path4KeySaving);
    }
}
