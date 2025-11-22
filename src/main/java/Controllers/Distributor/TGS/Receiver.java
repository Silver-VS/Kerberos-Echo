package Controllers.Distributor.TGS;

import Model.KeyDistributor;

import java.net.ServerSocket;

public class Receiver {
    public static void main(String[] args) throws Exception {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        ServerSocket serverSocket = new ServerSocket(5501);

        String whoAmI = "TGS";
        String senderName;
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        senderName = "Server";
        KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving);

    }
}
