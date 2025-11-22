package Model;

import java.io.Serializable;

/**
 * Represents a simplified Kerberos-style ticket.
 * <p>
 * A ticket is a serializable data structure containing identifiers,
 * timestamps, network address information and (optionally) a key.
 * It is used as the building block inside {@link UTicket}, which acts
 * as the envelope sent over the network.
 * <p>
 * Typical uses:
 * <ul>
 *   <li>Authentication request tickets (e.g. {@code idTicket = "request"}).</li>
 *   <li>Ticket-Granting Ticket (TGT).</li>
 *   <li>Service tickets (e.g. {@code idTicket = "serviceTicket"}).</li>
 *   <li>Authenticators ({@code idTicket = "auth"}).</li>
 *   <li>Responses to the client ({@code idTicket = "responseToClient"}).</li>
 * </ul>
 *
 * Fields are stored as strings for simplicity and may contain:
 * <ul>
 *   <li>{@code firstId}, {@code secondId}: client and service principals.</li>
 *   <li>{@code addressIP}: client IP address.</li>
 *   <li>{@code lifetime}: validity interval expressed as a string.</li>
 *   <li>{@code timeStamp}: time at which the ticket/authenticator was created.</li>
 *   <li>{@code key}: symmetric key (session key) encoded in Base64.</li>
 * </ul>
 *
 * @author Silver-VS
 */
public class Ticket implements Serializable {

    private String idTicket;
    private String firstId;
    private String secondId;
    private String addressIP;
    private String lifetime;
    private String timeStamp;
    private String key;

    public Ticket() {
    }

    public Ticket(String idTicket, String firstId, String secondId, String addressIP, String lifetime,
                  String timeStamp, String key) {
        this.idTicket = idTicket;
        this.firstId = firstId;
        this.secondId = secondId;
        this.addressIP = addressIP;
        this.lifetime = lifetime;
        this.timeStamp = timeStamp;
        this.key = key;
    }

    public String getIdTicket() {
        return idTicket;
    }

    public void setIdTicket(String idTicket) {
        this.idTicket = idTicket;
    }

    public String getFirstId() {
        return firstId;
    }

    public void setFirstId(String firstId) {
        this.firstId = firstId;
    }

    public String getSecondId() {
        return secondId;
    }

    public void setSecondId(String secondId) {
        this.secondId = secondId;
    }

    public String getAddressIP() {
        return addressIP;
    }

    public void setAddressIP(String addressIP) {
        this.addressIP = addressIP;
    }

    public String getLifetime() {
        return lifetime;
    }

    public void setLifetime(String lifetime) {
        this.lifetime = lifetime;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public boolean isFilledFirstId() {
        return getFirstId() != null;
    }

    public boolean isFilledSecondId() {
        return getSecondId() != null;
    }

    public boolean isFilledAddressIP() {
        return getAddressIP() != null;
    }

    public boolean isFilledLifetime() {
        return getLifetime() != null;
    }

    public boolean isFilledTimeStamp() {
        return getTimeStamp() != null;
    }

    public boolean isFilledKey() {
        return getKey() != null;
    }
}