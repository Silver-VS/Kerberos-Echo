package Controllers.Distributor.Client;

import Model.KeyDistributor;

/**
 * Sender-side component for establishing symmetric keys from the Client
 * towards another principal (typically the AS).
 * <p>
 * This class is part of the <em>Distributor phase</em>. It connects to the
 * peer's Receiver socket, sends the Client's public key, and receives a
 * symmetric key encrypted with that public key. The symmetric key is then
 * stored under {@code Security/SecretVault/Connection/} as
 * {@code Symmetric-Client-<Peer>.key}.
 *
 * The corresponding Receiver (on the peer side) must be running before
 * this Sender is started.
 *
 * @author Silver-VS
 */
public class Sender {

    /**
     * Initiates a Distributor key exchange from the Client to a peer (for
     * example, the AS), resulting in a stored long-term symmetric key that
     * will later be used during the Kerberos phase.
     *
     * @param args not used
     * @throws Exception if network I/O or key operations fail
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        String receiverHost = "localhost";
        int connectionPort = 5521;

        String whoAmI = "Client";
        String receiverName = "AS";
        String path4KeyRetrieval = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        KeyDistributor.publicSenderSecretReceiver(receiverHost, connectionPort, receiverName, whoAmI,
                path4KeyRetrieval, path4KeySaving);
    }
}