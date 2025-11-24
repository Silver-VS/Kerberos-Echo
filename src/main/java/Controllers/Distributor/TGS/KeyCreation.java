package Controllers.Distributor.TGS;

import Security.Model.KeyMethods;

/**
 * Bootstrap utility for the Ticket Granting Server (TGS) cryptographic material.
 * <p>
 * As part of the <em>Distributor phase</em>, this class generates the RSA key
 * pair for the TGS and stores it under:
 *
 * <pre>
 *   Security/SecretVault/Generated/publicTGS.key
 *   Security/SecretVault/Generated/privateTGS.key
 * </pre>
 *
 * In a multi-node environment, this should be executed only on the TGS host.
 *
 * The resulting RSA keys are later used by the key-distribution step to
 * establish symmetric keys between:
 *
 * <ul>
 *   <li>TGS ↔ AS</li>
 *   <li>TGS ↔ Server</li>
 *   <li>TGS ↔ Client (via the AS-issued session key K_c,tgs)</li>
 * </ul>
 *
 * Configuration (paths) is intentionally hardcoded for demo purposes.
 *
 * @author Silver-VS
 */
public class KeyCreation {

    /**
     * Generates an RSA key pair for the Ticket Granting Server (TGS) and writes
     * it into {@code SecretVault/Generated}.
     *
     * @param args not used
     * @throws Exception if key generation or file I/O fails
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "TGS");
    }
}
