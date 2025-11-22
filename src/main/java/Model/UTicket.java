package Model;

import Security.Model.Encryption;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.util.ArrayList;

/**
 * Container and utility for Kerberos tickets sent over the network.
 * <p>
 * A {@code UTicket} (User Ticket) is the actual object that is serialized
 * and transmitted via sockets. It holds a list of {@link Ticket} instances
 * and provides convenience methods to:
 * <ul>
 *   <li>Create standard tickets (request, authenticator, TGT, service ticket,
 *       response to client, etc.).</li>
 *   <li>Encrypt/decrypt all relevant fields of a specific ticket using a
 *       symmetric key.</li>
 *   <li>Search tickets by their {@code idTicket}.</li>
 *   <li>Print tickets for debugging or demonstration purposes.</li>
 * </ul>
 * Conceptually, the {@code UTicket} is what the client "sees" and sends,
 * while some of the embedded tickets (e.g. TGT, serviceTicket) are
 * intended to be opaque to the client and only readable by the corresponding
 * Kerberos service.
 * <br><br>
 * This class should be used to create, encrypt and decrypt all the Tickets created
 * to transit in the network.
 *
 * @author Silver_VS
 */
public class UTicket implements Serializable {
    private final ArrayList<Ticket> tickets;

    /**
     * Method to initialize the arraylist for a new UTicket.
     */
    public UTicket() {
        tickets = new ArrayList<>();
    }

    public ArrayList<Ticket> getTickets() {
        return tickets;
    }

    public Ticket searchTicket(String id) {
        for (Ticket i : tickets) {
            if (i.getIdTicket().equals(id)) {
                return i;
            }
        }
        return null;
    }

    public void addTicket(Ticket ticket) {
        tickets.add(ticket);
    }

    /**
     * Creates the initial request ticket that the client sends to the AS.
     * <p>
     * This method generates a {@link Ticket} with:
     * <ul>
     *   <li>{@code idTicket = "request"}</li>
     *   <li>{@code firstId = userID}</li>
     *   <li>{@code secondId = serviceID}</li>
     *   <li>{@code lifetime = requestedLifetime}</li>
     * </ul>
     *
     * @param userID           identifier of the client principal
     * @param serviceID        identifier of the requested service
     * @param requestedLifetime requested lifetime for the issued ticket(s)
     */
    public void generateRequest(String userID, String serviceID, String requestedLifetime) {
        Ticket request = new Ticket();
        request.setIdTicket("request");
        request.setFirstId(userID);
        request.setSecondId(serviceID);
        request.setLifetime(requestedLifetime);
        addTicket(request);
    }

    /**
     * Generates a ticket that represents a response directed to the client.
     * <p>
     * This ticket is typically used to carry a session key from a Kerberos
     * service (AS, TGS) to the client.
     *
     * @param firstId   identifier of the service or server (e.g. {@code "TGS"}, {@code "Server"})
     * @param timeStamp creation time of the response
     * @param lifetime  validity interval granted
     * @param key       session key encoded as Base64
     */
    public void generateResponse4User(String firstId, String timeStamp, String lifetime, String key) {
        Ticket response = new Ticket();
        response.setIdTicket("responseToClient");
        response.setFirstId(firstId);
        response.setTimeStamp(timeStamp);
        response.setLifetime(lifetime);
        response.setKey(key);
        addTicket(response);
    }

    /**
     * Generic helper to create an arbitrary ticket with all fields.
     *
     * @param nameOfTicket logical ticket id (e.g. {@code "TGT"}, {@code "serviceTicket"})
     * @param firstID      usually the client identifier
     * @param secondID     usually the service/server identifier
     * @param timeStamp    creation time
     * @param addressIP    client IP address
     * @param lifetime     validity interval
     * @param key          associated key (often a session key) as Base64 string
     */
    public void generateTicket(String nameOfTicket, String firstID, String secondID, String timeStamp, String addressIP,
                               String lifetime, String key) {
        addTicket(
                new Ticket(nameOfTicket, firstID, secondID, addressIP, lifetime, timeStamp, key)
        );
    }

    /**
     * Adds a request ticket specifically for the TGS, indicating the desired service.
     *
     * @param serviceID identifier of the target service/server
     */
    public void request4TGS(String serviceID) {
        Ticket request = new Ticket();
        request.setIdTicket("request4TGS");
        request.setFirstId(serviceID);
        addTicket(request);
    }

    /**
     * Adds an authenticator ticket.
     * <p>
     * The authenticator typically includes:
     * <ul>
     *   <li>The client identity ({@code firstID}).</li>
     *   <li>The client IP address.</li>
     *   <li>A fresh timestamp.</li>
     * </ul>
     *
     * @param firstID   client identifier
     * @param addressIP client IP address
     * @param timeStamp creation time of the authenticator
     */
    public void addAuthenticator(String firstID, String addressIP, String timeStamp) {
        Ticket auth = new Ticket();
        auth.setIdTicket("auth");
        auth.setFirstId(firstID);
        auth.setAddressIP(addressIP);
        auth.setTimeStamp(timeStamp);
        addTicket(auth);
    }


    public boolean[] getFilled(Ticket ticket) {
        boolean[] existingFields = new boolean[6];
        existingFields[0] = ticket.isFilledFirstId();
        existingFields[1] = ticket.isFilledSecondId();
        existingFields[2] = ticket.isFilledAddressIP();
        existingFields[3] = ticket.isFilledLifetime();
        existingFields[4] = ticket.isFilledTimeStamp();
        existingFields[5] = ticket.isFilledKey();
        return existingFields;
    }

    /**
     * Encrypts all populated fields of the ticket identified by {@code id}
     * using the provided symmetric key.
     *
     * @param key symmetric key to use (typically DES)
     * @param id  ticket id (e.g. {@code "TGT"}, {@code "auth"})
     * @return {@code true} if encryption succeeds, {@code false} otherwise
     */
    public boolean encryptTicket(SecretKey key, String id) {
        try {
            Ticket toEncrypt = searchTicket(id);

            if (toEncrypt == null)
                return false;

            boolean[] existingFields = getFilled(toEncrypt);
            if (existingFields[0])
                toEncrypt.setFirstId(Encryption.symmetricEncrypt(key, toEncrypt.getFirstId()));
            if (existingFields[1])
                toEncrypt.setSecondId(Encryption.symmetricEncrypt(key, toEncrypt.getSecondId()));
            if (existingFields[2])
                toEncrypt.setAddressIP(Encryption.symmetricEncrypt(key, toEncrypt.getAddressIP()));
            if (existingFields[3])
                toEncrypt.setLifetime(Encryption.symmetricEncrypt(key, toEncrypt.getLifetime()));
            if (existingFields[4])
                toEncrypt.setTimeStamp(Encryption.symmetricEncrypt(key, toEncrypt.getTimeStamp()));
            if (existingFields[5])
                toEncrypt.setKey(Encryption.symmetricEncrypt(key, toEncrypt.getKey()));
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Decrypts all populated fields of the ticket identified by {@code id}
     * using the provided symmetric key.
     *
     * @param key symmetric key to use
     * @param id  ticket id
     * @return {@code true} if decryption succeeds, {@code false} otherwise
     */
    public boolean decryptTicket(SecretKey key, String id) {
        try {
            Ticket toDecrypt = searchTicket(id);

            if (toDecrypt == null)
                return false;

            boolean[] existingFields = getFilled(toDecrypt);
            if (existingFields[0]) {
                toDecrypt.setFirstId(Encryption.symmetricDecrypt(key, toDecrypt.getFirstId()));
            }
            if (existingFields[1]) {
                toDecrypt.setSecondId(Encryption.symmetricDecrypt(key, toDecrypt.getSecondId()));
            }
            if (existingFields[2]) {
                toDecrypt.setAddressIP(Encryption.symmetricDecrypt(key, toDecrypt.getAddressIP()));
            }
            if (existingFields[3]) {
                toDecrypt.setLifetime(Encryption.symmetricDecrypt(key, toDecrypt.getLifetime()));
            }
            if (existingFields[4]) {
                toDecrypt.setTimeStamp(Encryption.symmetricDecrypt(key, toDecrypt.getTimeStamp()));
            }
            if (existingFields[5]) {
                toDecrypt.setKey(Encryption.symmetricDecrypt(key, toDecrypt.getKey()));
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void printTicket(UTicket uTicket) {
        for (Ticket i : uTicket.getTickets()) {
            printTicket(uTicket, i.getIdTicket());
        }
    }

    public void printTicket(UTicket uTicket, String ticketId) {
        Ticket ticket = uTicket.searchTicket(ticketId);
        if (ticket != null) {
            boolean[] filled = uTicket.getFilled(ticket);
            System.out.println("idTicket: " + ticket.getIdTicket());
            if (filled[0]) {
                System.out.println("firstId: " + ticket.getFirstId());
            }
            if (filled[1]) {
                System.out.println("secondId: " + ticket.getSecondId());
            }
            if (filled[2]) {
                System.out.println("addressIP: " + ticket.getAddressIP());
            }
            if (filled[3]) {
                System.out.println("lifetime: " + ticket.getLifetime());
            }
            if (filled[4]) {
                System.out.println("timeStamp: " + ticket.getTimeStamp());
            }
            if (filled[5]) {
                System.out.println("key: " + ticket.getKey());
            }
        }
    }

}
