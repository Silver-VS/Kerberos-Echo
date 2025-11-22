package Controllers.Distributor.AS;

import Security.Model.KeyMethods;

/**
 * Key generation entry point for the Authentication Server (AS).
 * <p>
 * This class is responsible for creating the long-term cryptographic keys
 * used by the AS. The generated keys are stored under the
 * {@code Security/SecretVault/Generated} directory.
 * <p>
 * In a real deployment this step would typically be performed once during
 * provisioning or key rotation; in this educational project it is exposed
 * as a standalone {@code main} method for clarity and manual control.
 *
 * @author Silver-VS
 */
public class KeyCreation {

    /**
     * Generates the key material for the Authentication Server (AS).
     * <p>
     * Currently the base project path is hardcoded, and keys are written to:
     * {@code <projectPath>/src/main/java/Security/SecretVault/Generated/}.
     * <p>
     * Future enhancement: read the project path from command-line arguments
     * or configuration (e.g. under {@code resources/}) instead of hardcoding it.
     *
     * @param args not used
     * @throws Exception if key generation fails for any reason
     */
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "AS");
    }
}
