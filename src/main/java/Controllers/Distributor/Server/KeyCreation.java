package Controllers.Distributor.Server;

import Security.Model.KeyMethods;

/**
 * Bootstrap utility for the Application Server cryptographic material.
 * <p>
 * Part of the <em>Distributor phase</em>, this class generates the RSA key
 * pair for the Server and writes it to:
 *
 * <pre>
 *   Security/SecretVault/Generated/publicServer.key
 *   Security/SecretVault/Generated/privateServer.key
 * </pre>
 *
 * In a distributed setup, only the machine hosting the protected service
 * (the application server) should run this class.
 *
 * The RSA keys produced here are later used by the Distributor Sender/Receiver
 * classes to establish long-term symmetric keys between the Server and the TGS
 * (and optionally other principals).
 *
 * Paths are hardcoded for demonstration and can be adjusted by editing
 * {@code projectPath}.
 *
 * @author Silver-VS
 */
public class KeyCreation {

    /**
     * Generates an RSA key pair for the Server and writes it into
     * {@code SecretVault/Generated}.
     *
     * @param args not used
     * @throws Exception if key generation or file I/O fails
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "Server");
    }
}
