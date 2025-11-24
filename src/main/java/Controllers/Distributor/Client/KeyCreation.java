package Controllers.Distributor.Client;

import Security.Model.KeyMethods;

/**
 * Bootstrap utility for the Client cryptographic material.
 * <p>
 * This class belongs to the <em>Distributor phase</em>. It generates the
 * RSA key pair for the Client and stores it under:
 *
 * <pre>
 *   Security/SecretVault/Generated/publicClient.key
 *   Security/SecretVault/Generated/privateClient.key
 * </pre>
 *
 * In a multi-node scenario, it would be executed only on the machine
 * representing the Client. Once generated, these keys are used in the
 * key-distribution step to derive long-term symmetric keys between:
 *
 * <ul>
 *   <li>Client ↔ AS (K_as,c)</li>
 *   <li>Client ↔ TGS (K_c,tgs)</li>
 *   <li>Client ↔ Server (K_c,s)</li>
 * </ul>
 *
 * This class does not take command-line arguments. The {@code projectPath}
 * must be adapted to your local checkout.
 *
 * @author Silver-VS
 */
public class KeyCreation {

    /**
     * Generates an RSA key pair for the Client and writes it into
     * {@code SecretVault/Generated}.
     *
     * @param args not used
     * @throws Exception if key generation or file I/O fails
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "Client");
    }
}
