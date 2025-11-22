import Model.TimeMethods;

import java.sql.Timestamp;
import java.time.Instant;

public class TimeTest {
    public static void main(String[] args) throws InterruptedException {
        Timestamp now = Timestamp.from(Instant.now());
        now.setTime(now.getTime() + TimeMethods.getMillis(5));
        Timestamp compareNow = Timestamp.from(Instant.now());
        if(now.compareTo(compareNow) == 0) System.out.println("Tiempo exacto");
        else if(now.compareTo(compareNow) > 0) System.out.println("Aún a tiempo");
        else System.out.println("Ya expiró");

    }
}
