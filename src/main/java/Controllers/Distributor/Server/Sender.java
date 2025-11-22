package Controllers.Distributor.Server;

import Model.KeyDistributor;

public class Sender {
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