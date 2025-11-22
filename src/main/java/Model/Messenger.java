package Model;

import Security.Model.Encryption;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Low-level networking helper for sending and receiving objects over TCP sockets.
 * <p>
 * This class centralizes all socket and serialization operations used by the
 * Kerberos demo:
 * <ul>
 *   <li>Opening client and server sockets.</li>
 *   <li>Sending and receiving {@link UTicket} objects.</li>
 *   <li>Exchanging public keys and symmetric keys wrapped in {@link KeyObject}.</li>
 *   <li>Sending simple boolean acknowledgements.</li>
 * </ul>
 * The actual cryptographic operations (encryption/decryption, key conversion)
 * are delegated to {@link Encryption} and {@link KeyMethods}. All messages
 * are serialized using Java's {@link ObjectInputStream}/{@link ObjectOutputStream}.
 */
public class Messenger {

    /**
     * Creates a client socket connected to the given host and port.
     * <p>
     * This is the entry point used by "sender" roles that need to initiate a
     * connection (e.g. the client contacting the AS, or one actor contacting
     * another during key distribution).
     *
     * @param receiverHost   hostname or IP address of the remote endpoint
     * @param connectionPort TCP port on which the remote endpoint is listening
     * @return an established {@link Socket}
     * @throws IOException if the connection cannot be established
     */
    public static Socket socketInitializer(String receiverHost, int connectionPort) throws IOException {
        //  We indicate the destination of the Ticket, establishing the IP where it will be received and the
        //  "channel" or port where both all comms will be held.
        //  The socket indicated in here must be already running in the receiverHost, or the connection
        //  won't be established.
        return new Socket(receiverHost, connectionPort);
    }

    /**
     * Creates and binds a {@link ServerSocket} to the specified port.
     *
     * @param receiverPort TCP port on which this process should listen
     * @return a {@link ServerSocket} ready to accept connections,
     * or {@code null} if the socket cannot be created
     */
    public static ServerSocket serverSocketInitializer(int receiverPort) {
        //  A server socket takes a request and can send a response without the need to start a second socket.
        try {
            return new ServerSocket(receiverPort);
        } catch (IOException e) {
            return null;
        }
    }

    public static ObjectOutputStream objectSenderInitializer(Socket socket) {
        try {
            //  We state that we are sending something through an outputStream.
            OutputStream outputStream = socket.getOutputStream();
            //  Now we clarify that we are sending an object through said stream.
            return new ObjectOutputStream(outputStream);
        } catch (Exception e) {
            System.out.println("Error al obtener OutputStream del socket: " + socket.toString());
            return null;
        }
    }

    /**
     * Accepts an incoming connection from the given {@link ServerSocket}.
     *
     * @param serverSocket server socket that is already bound and listening
     * @return the accepted {@link Socket} or {@code null} if an {@link IOException}
     * occurs during {@link ServerSocket#accept()}
     */
    public static Socket requestAccepter(ServerSocket serverSocket) {

        try {
            //  Now we will accept incoming messages from the established channel.
            return serverSocket.accept();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Receives a public key from the remote endpoint.
     * <p>
     * The remote side is expected to send a serialized {@link KeyObject} whose
     * {@code publicKey} field contains the key encoded as a string. This method
     * reads the object, extracts the string representation and converts it to
     * a {@link PublicKey} using {@link KeyMethods#convertString2Public(String)}.
     *
     * @param socket an open socket connected to the remote endpoint
     * @return the received {@link PublicKey}, or {@code null} if an error occurs
     */
    public static PublicKey receivePublic(Socket socket) {

        try {
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectReceiver = new ObjectInputStream(inputStream);
            KeyObject keyObject = (KeyObject) objectReceiver.readObject();
            String receivedString = keyObject.getPublicKey();
            return KeyMethods.convertString2Public(receivedString);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Sends a {@link UTicket} to a remote host and waits for a {@link UTicket}
     * response.
     * <p>
     * This is used by the Kerberos protocol controllers to implement the
     * request/response pattern over TCP:
     * <ol>
     *   <li>Open a socket to {@code receiverHost:connectionPort}.</li>
     *   <li>Serialize and send the {@code ticket} using an {@link ObjectOutputStream}.</li>
     *   <li>Read the response {@link UTicket} from an {@link ObjectInputStream}.</li>
     *   <li>Close the socket and return the response ticket.</li>
     * </ol>
     *
     * @param receiverHost   hostname or IP address of the remote actor
     * @param connectionPort TCP port of the remote actor's controller
     * @param ticket         ticket to be sent (e.g. AS-REQ, TGS-REQ, AP-REQ)
     * @return the response {@link UTicket}, or {@code null} if an error occurs
     */
    public static UTicket ticketSender(String receiverHost, int connectionPort, UTicket ticket) {

        try {
            Socket socket = socketInitializer(receiverHost, connectionPort);

            //  Now we need to send the object through the connection.
            Objects.requireNonNull(objectSenderInitializer(socket)).writeObject(ticket);

            //  We show in the console what are we trying to send.
            System.out.print("\nTicket enviado:\n");
            ticket.printTicket(ticket);
            System.out.print("\ntermina ticket enviado.\n");

            //  So now we think it has been sent, but we need to be sure of it.
            //  We are going to be receiving information from the socket to confirm
            //  the reception of the object.
            InputStream inputStream = socket.getInputStream();
            //  The server will be returning a boolean, which is already serialized, so we can make
            //  use of the already existing methods for sending and receiving booleans.
            ObjectInputStream objectReceiver = new ObjectInputStream(inputStream);
            //  At this point, we are reading the information sent as a response for our request.
            UTicket ticket1 = (UTicket) objectReceiver.readObject();

            System.out.print("\nRecibido en red:\n");
            ticket1.printTicket(ticket1);
            System.out.print("\nTermina recibo en red\n");

            //  Now that we have a response we can close the communication channel.
            socket.close();

            return ticket1;
        } catch (Exception e) {
            System.out.print("\nError al recibir el ticket." + "\nError:");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Implements the "send public key, receive symmetric key" pattern.
     * <p>
     * Protocol:
     * <ol>
     *   <li>Wrap the provided {@code keyToSend} in a {@link KeyObject} and send it.</li>
     *   <li>Wait for a {@link KeyObject} containing a symmetric key encrypted
     *       with the same public key.</li>
     *   <li>Decrypt the symmetric key with the provided {@code privateKey}
     *       using {@link Encryption#privateDecrypt(PrivateKey, String)}.</li>
     *   <li>Convert the decrypted string into a {@link SecretKey} using
     *       {@link KeyMethods#convertString2Key(String)} and return it.</li>
     * </ol>
     *
     * @param socket     open socket to the remote endpoint
     * @param keyToSend  public key that will be sent to the remote side
     * @param privateKey private key used to decrypt the received symmetric key
     * @return the symmetric {@link SecretKey}, or {@code null} if an error occurs
     */
    public static SecretKey sendPublicReceiveSecret(Socket socket, PublicKey keyToSend, PrivateKey privateKey) {

        try {
            KeyObject keyObject = new KeyObject();

            String key2String = KeyMethods.convertAnyKey2String(keyToSend);

            keyObject.setPublicKey(key2String);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(keyObject);
            System.out.println("La llave publica ha sido enviada exitosamente.");
            String receivedEncrypted = awaitSecret(socket);
            System.out.println("La llave secreta encriptada ha sido recibida exitosamente.");
            String secretDecrypted = Encryption.privateDecrypt(privateKey, receivedEncrypted);
            System.out.println("Se ha desencriptado exitosamente la llave privada");

            return KeyMethods.convertString2Key(secretDecrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static String awaitSecret(Socket socket) {

        try {
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            KeyObject keyObject = (KeyObject) objectInputStream.readObject();
            return keyObject.getSecretKey();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Reads a {@link UTicket} object from the given socket.
     * <p>
     * This method is used on the server side of the Kerberos protocol to
     * retrieve the client's request.
     *
     * @param socket an accepted socket representing the client connection
     * @return the received {@link UTicket}, or {@code null} if an error occurs
     */

    public static UTicket ticketAccepter(Socket socket) {

        try {
            //  Once accepted, we are going to need to read the information received.
            InputStream inputStream = socket.getInputStream();
            //  We specify that we will be reading an object from said stream.
            ObjectInputStream objectReceiver = new ObjectInputStream(inputStream);
            //  Now we need to read the Ticket.
            return (UTicket) objectReceiver.readObject();
        } catch (Exception e) {
            System.out.println("No se ha podido recibir el ticket." + "\nError: ");
            e.printStackTrace();
            return null;
        }
    }


    /**
     * Sends a boolean response over the given socket and closes it.
     *
     * @param socket   open socket to the remote endpoint
     * @param response boolean value to send
     * @return {@code true} if the response was sent successfully, {@code false} otherwise
     */
    public static boolean booleanResponder(Socket socket, boolean response) {

        try {
            //  We send the response ticket.
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeBoolean(response);
            //  We can proceed to close the receiving socket.
            socket.close();
            return true;
        } catch (Exception e) {
            System.out.println("\nNo se ha podido enviar una respuesta (boolean responder)." + "\nError: ");
            e.printStackTrace();
            return false;
        }
    }


    /**
     * Sends a {@link UTicket} as a response over the given socket and closes it.
     *
     * @param socket         open socket to the remote endpoint
     * @param ticketResponse ticket to be sent as the response
     * @return {@code true} if the ticket was sent successfully, {@code false} otherwise
     */
    public static boolean ticketResponder(Socket socket, UTicket ticketResponse) {

        try {
            //  We send the response ticket.
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(ticketResponse);

            //  We print the ticket response.
            ticketResponse.printTicket(ticketResponse);
            System.out.println("\nEl ticket ha sido enviado exitosamente.");

            //  We can proceed to close the receiving socket.
            socket.close();
            return true;
        } catch (Exception e) {
            System.out.println("\nHa ocurrido un error al enviar el ticket.");
            System.out.println("Error: ");
            e.printStackTrace();
            return false;
        }
    }


    /**
     * Sends a symmetric key encrypted with the provided public key.
     * <p>
     * The symmetric key is converted to a string, encrypted using
     * {@link Encryption#publicEncrypt(PublicKey, String)}, wrapped into a
     * {@link KeyObject}, serialized and written to the socket.
     *
     * @param socket    open socket to the remote endpoint
     * @param secretKey symmetric key to be encrypted and sent
     * @param publicKey remote actor's public key
     * @return {@code true} if the key was sent successfully, {@code false} otherwise
     */
    public static boolean secretResponder(Socket socket, SecretKey secretKey, PublicKey publicKey) {

        try {
            String encryptedString = Encryption.publicEncrypt(publicKey, KeyMethods.convertAnyKey2String(secretKey));
            System.out.println("Se ha encriptado exitosamente la llave secreta.");
            KeyObject keyObject = new KeyObject();
            keyObject.setSecretKey(encryptedString);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(keyObject);
            socket.close();
            System.out.println("\nLa llave secreta encriptada ha sido enviada exitosamente.");
            return true;
        } catch (Exception e) {
            System.out.println("\nHa ocurrido un error al enviar la llave secreta.");
            System.out.println("Error: ");
            e.printStackTrace();
            return false;
        }
    }
}
