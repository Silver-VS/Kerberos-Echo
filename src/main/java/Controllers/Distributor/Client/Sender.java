package Controllers.Distributor.Client;

import Model.KeyDistributor;

public class Sender {
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