package Controllers.Kerberos.Client;

import Model.Messenger;
import Model.UTicket;

import javax.crypto.SecretKey;

/**
 * @author Silver-VS
 */

public class RequestAccess {

    public static UTicket startAuth(String userID, String serviceID, String requestedLifetime,
                                    String addressIP_AS, int connectionPort_AS) {

        UTicket serviceRequest = new UTicket();
        serviceRequest.generateRequest(userID, serviceID, requestedLifetime);
        return Messenger.ticketSender(addressIP_AS, connectionPort_AS, serviceRequest);
    }

    public static UTicket followTGS(UTicket ticketFromAS, String serviceID, SecretKey sessionKeyClientTGS,
                                    String requestedLifetime, String userID, String timeStamp,
                                    String addressIP_Self, String addressIP_TGS, int connectionPort_TGS) {

        UTicket followUpTicketTGS = new UTicket();
        followUpTicketTGS.addTicket(ticketFromAS.searchTicket("TGT"));
        followUpTicketTGS.request4TGS(serviceID);
        followUpTicketTGS.addAuthenticator(userID, addressIP_Self, timeStamp);
        System.out.println("Tickets a enviar:\n");
        followUpTicketTGS.printTicket(followUpTicketTGS);

        if (followUpTicketTGS.encryptTicket(sessionKeyClientTGS, "auth"))
            System.out.println("\nTicket auth encriptado exitosamente con llave de sesi\u00F3n Client - TGS");
        else {
            System.out.println("\nHa ocurrido un error al encriptar el ticket auth.");
            System.exit(-1);
        }
        try {
            return Messenger.ticketSender(addressIP_TGS, connectionPort_TGS, followUpTicketTGS);
        } catch (Exception e) {
            System.out.println("Error al recibir respuesta.");
            System.out.println("Error: ");
            e.printStackTrace();
            return null;
        }

    }

    public static UTicket askForService(UTicket ticketFromTGS, String userID, String timeStamp,
                                        SecretKey secretKey, String addressIP_Self,
                                        String addressIP_Server, int connectionPort_Server) {

        UTicket askForService = new UTicket();
        askForService.addTicket(ticketFromTGS.searchTicket("serviceTicket"));
        askForService.addAuthenticator(userID, addressIP_Self, timeStamp);

        if(askForService.encryptTicket(secretKey, "auth"))
            System.out.println("Ticket auth encriptado exitosamente con llave de sesi\u00F3n Client - Server.");
        else {
            System.out.println("Ha ocurrido un error al encriptar el ticket auth.");
            System.exit(-1);
        }
        return Messenger.ticketSender(addressIP_Server, connectionPort_Server, askForService);

    }
}
