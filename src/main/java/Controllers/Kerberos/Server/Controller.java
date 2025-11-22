package Controllers.Kerberos.Server;

import Model.Messenger;

import java.net.ServerSocket;

/**
 * @author Silver-VS
 */

public class Controller {
    public static void main(String[] args) {

        String projectPath = "D:\\Kerberos_Echo\\Kerberos";
        String addressIP_Self = "localhost";
        int receivingPort = 1203;


        String path4SecretKeyRetrieving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";


        ServerSocket serverSocket = Messenger.serverSocketInitializer(receivingPort);

        if (serverSocket == null) {
            System.out.println("No se ha podido iniciar el Servidor.");
            System.exit(-1);
        }

        System.out.println("Servidor iniciado.");

        do {
            System.out.println("En espera de petici\u00F3n...");

            ProcessRequest.processUserRequest(
                    Messenger.requestAccepter(serverSocket),
                    path4SecretKeyRetrieving, addressIP_Self
            );
            System.out.println("Respuesta enviada al cliente.");
        } while (!serverSocket.isClosed());
    }
}
