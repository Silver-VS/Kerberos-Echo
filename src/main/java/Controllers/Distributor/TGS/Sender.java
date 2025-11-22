package Controllers.Distributor.TGS;

import Model.KeyDistributor;

public class Sender {
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        int connectionPort = 5521;

        String whoAmI = "TGS";
        String receiverHost = "localhost";
        String receiverName = "AS";
        String path4KeyRetrieval = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        KeyDistributor.publicSenderSecretReceiver(receiverHost, connectionPort, receiverName, whoAmI,
                path4KeyRetrieval, path4KeySaving);
    }
}