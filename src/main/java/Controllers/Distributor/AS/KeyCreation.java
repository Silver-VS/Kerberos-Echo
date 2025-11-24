package Controllers.Distributor.AS;

import Security.Model.KeyMethods;

/**
 * Bootstrap utility for the Authentication Server (AS) cryptographic material.
 * <p>
 * This class belongs to the <em>Distributor phase</em> of the project.
 * It is intended to be run once (or whenever you want to rotate keys) to
 * generate the RSA key pair for the AS and store it under:
 *
 * <pre>
 *   Security/SecretVault/Generated/publicAS.key
 *   Security/SecretVault/Generated/privateAS.key
 * </pre>
 *
 * In a multi-node deployment, this class would be executed only on the
 * machine hosting the AS.
 *
 * The corresponding symmetric keys used for communication with other
 * principals (Client, TGS) are established later via the Sender/Receiver
 * classes and {@link Model.KeyDistributor}.
 *
 * This class does not take command-line arguments. Paths are currently
 * hardcoded for demonstration purposes; adjust {@code projectPath} as needed.
 *
 * @author Silver-VS
 */
public class KeyCreation {

    /**
     * Generates an RSA key pair for the Authentication Server (AS) and writes
     * it into the {@code SecretVault/Generated} directory.
     *
     * @param args not used
     * @throws Exception if key generation or file I/O fails
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "AS");
    }
}
