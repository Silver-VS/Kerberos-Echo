package Controllers.Distributor.AS;

import Model.KeyDistributor;

import java.net.ServerSocket;

public class Receiver {
    public static void main(String[] args) throws Exception {

        ServerSocket serverSocket = new ServerSocket(5521);
        String whoAmI = "AS";
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String senderName;
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        senderName = "Client";
        if (!KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving))
            System.out.println("Ha ocurrido un error");
        senderName = "TGS";
        if (!KeyDistributor.receiver(serverSocket, senderName, whoAmI, path4KeySaving))
            System.out.println("Ha ocurrido un error");
    }
}
