package Controllers.Distributor.Server;

import Security.Model.KeyMethods;

/**
 * Key generation entry point for the Service provider (Server),
 * the one the user is ultimately trying to connect to.
 * <p>
 * This class is responsible for creating the long-term cryptographic keys
 * used by the Server. The generated keys are stored under the
 * {@code Security/SecretVault/Generated} directory.
 * <p>
 * In a real deployment this step would typically be performed once during
 * provisioning or key rotation; in this educational project it is exposed
 * as a standalone {@code main} method for clarity and manual control.
 */
public class KeyCreation {
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "Server");
    }
}
