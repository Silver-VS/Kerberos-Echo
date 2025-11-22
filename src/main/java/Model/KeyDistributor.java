package Model;

import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
/**
 * Utility class for bootstrapping symmetric keys between Kerberos actors.
 * <p>
 * This class encapsulates the initial key exchange protocol used by the
 * {@code Controllers.Distributor} package:
 * <ul>
 *   <li>One side (the "sender") connects to a remote host, sends its public key
 *       and receives a newly generated symmetric key encrypted with that public key.</li>
 *   <li>The other side (the "receiver") accepts the connection, stores the
 *       sender's public key, generates the symmetric key and returns it
 *       encrypted.</li>
 * </ul>
 * The established symmetric keys are persisted using {@link KeyMethods} under
 * {@code Security/SecretVault/Connection} so they can later be used by the
 * Kerberos controllers.
 */
public class KeyDistributor {

    /**
     * Initiates the key exchange from the "sender" side.
     * <p>
     * Protocol:
     * <ol>
     *   <li>Open a socket to the remote host and port.</li>
     *   <li>Load this actor's public/private key pair from
     *       {@code path4KeysRetrieval}.</li>
     *   <li>Send the public key to the remote side using
     *       {@link Messenger#sendPublicReceiveSecret(Socket, PublicKey, PrivateKey)}.</li>
     *   <li>Receive the symmetric key encrypted with the public key, decrypt it
     *       with the private key and store it under
     *       {@code Security/SecretVault/Connection} using {@link KeyMethods#saveSecret}.</li>
     * </ol>
     *
     * @param receiverHost      hostname or IP address of the remote actor
     * @param connectionPort    TCP port on which the remote actor is listening
     * @param whosResponding    logical name of the remote actor (e.g. {@code "AS"})
     *                           as used for naming the stored secret key
     * @param whoAreYou         logical name of the local actor (e.g. {@code "TGS"})
     * @param path4KeysRetrieval path to the directory containing this actor's
     *                           generated key pair (private/public)
     * @param path4KeySaving    path to the directory where the symmetric key
     *                          for this pair of actors should be stored
     * @throws Exception if any step in the key exchange or persistence fails
     */
    public static void publicSenderSecretReceiver(String receiverHost, int connectionPort, String whosResponding,
                                                  String whoAreYou, String path4KeysRetrieval, String path4KeySaving)
            throws Exception {

        Socket socket = Messenger.socketInitializer(receiverHost, connectionPort);

        PublicKey publicKey = KeyMethods.recoverPublic(path4KeysRetrieval, whoAreYou);
        PrivateKey privateKey = KeyMethods.recoverPrivate(path4KeysRetrieval, whoAreYou);

        SecretKey secretKey = Messenger.sendPublicReceiveSecret(socket, publicKey, privateKey);
        KeyMethods.saveSecret(secretKey, path4KeySaving, whoAreYou, whosResponding);
    }

    /**
     * Handles the key exchange from the "receiver" side.
     * <p>
     * Protocol:
     * <ol>
     *   <li>Accept an incoming connection on the provided {@link ServerSocket}.</li>
     *   <li>Receive the remote actor's public key via
     *       {@link Messenger#receivePublic(Socket)} and store it under
     *       {@code Security/SecretVault/Connection}.</li>
     *   <li>Generate a new symmetric key using
     *       {@link KeyMethods#generateSecretKey()} and store it with a name that
     *       identifies both the local actor ({@code whoAreYou}) and the sender ({@code whoIsSending}).</li>
     *   <li>Encrypt the symmetric key with the received public key and send it
     *       back using {@link Messenger#secretResponder(Socket, SecretKey, PublicKey)}.</li>
     * </ol>
     *
     * @param serverSocket  server socket that will accept the incoming connection
     * @param whoIsSending  logical name of the remote actor initiating the key
     *                      exchange (e.g. {@code "Client"}, {@code "Server"})
     * @param whoAreYou     logical name of the local actor (e.g. {@code "TGS"})
     * @param path4KeySaving path to the directory where the public key and the
     *                       generated symmetric key should be stored
     * @return {@code true} if the symmetric key was sent back successfully,
     *         {@code false} otherwise
     * @throws Exception if any part of the protocol fails
     */
    public static boolean receiver(ServerSocket serverSocket, String whoIsSending,
                                   String whoAreYou, String path4KeySaving) throws Exception {

        System.out.println("Esperando solicitud del " + whoIsSending + ".");
        Socket socket = serverSocket.accept();
        PublicKey publicKey = Messenger.receivePublic(socket);
        KeyMethods.saveKey(publicKey, path4KeySaving, whoIsSending + "Received", true);
        System.out.println("La llave publica ha sido guardada exitosamente");
        SecretKey secretKey = KeyMethods.generateSecretKey();
        KeyMethods.saveSecret(secretKey, path4KeySaving, whoAreYou, whoIsSending);
        System.out.println("La llave secreta ha sido generada exitosamente.");
        return Messenger.secretResponder(socket, secretKey, publicKey);
    }
}
