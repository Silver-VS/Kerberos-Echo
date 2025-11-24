package Controllers.Distributor.Server;

import Model.KeyDistributor;

/**
 * Sender-side component for establishing symmetric keys from the Server
 * towards another principal (typically the TGS).
 * <p>
 * This class is part of the <em>Distributor phase</em>. It connects to the
 * peer's Receiver socket, sends the Server's public key, and receives a
 * symmetric key encrypted with that key. The symmetric key is stored as
 * {@code Symmetric-Server-<Peer>.key} under
 * {@code Security/SecretVault/Connection/}.
 *
 * The peer Receiver (for example, {@code Controllers.Distributor.TGS.Receiver})
 * must be started before this Sender.
 *
 * @author Silver-VS
 */
public class Sender {

    /**
     * Initiates a Distributor key exchange from the Server to a peer (for
     * example, the TGS), creating a long-term symmetric key to be used in
     * the Kerberos phase.
     *
     * @param args not used
     * @throws Exception if network I/O or key operations fail
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        String receiverHost = "localhost";
        int connectionPort = 5501;

        String whoAmI = "Server";
        String receiverName = "TGS";
        String path4KeyRetrieval = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        KeyDistributor.publicSenderSecretReceiver(receiverHost, connectionPort, receiverName, whoAmI,
                path4KeyRetrieval, path4KeySaving);
    }
}