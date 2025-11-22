package Controllers.Kerberos.TGS;

import Model.Messenger;

import java.net.ServerSocket;

/**
 * @author Silver-VS
 */

public class Controller {
    public static void main(String[] args) {

        int receivingPort = 1202;
        String projectPath = "D:\\Kerberos_Echo\\Kerberos";

        String path4SecretKeyRetrieving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";
        String path4SecretKeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        ServerSocket serverSocket = Messenger.serverSocketInitializer(receivingPort);

        if (serverSocket == null) {
            System.out.println("No se ha podido iniciar el Servidor.");
            System.exit(-1);
        }

        System.out.println("TGS iniciado.");

        do {
            System.out.println("En espera de petici\u00F3n...");
            if (
                    ProcessRequest.processUserRequest(
                            Messenger.requestAccepter(serverSocket),
                            path4SecretKeyRetrieving, path4SecretKeySaving
                    )
            ) {
                System.out.println("Respuesta enviada del TGS al cliente.");
            } else {
                System.out.println("Ha ocurrido un error en la respuesta.");
                System.out.println("Error: ");
            }
        } while (!serverSocket.isClosed());
    }
}
