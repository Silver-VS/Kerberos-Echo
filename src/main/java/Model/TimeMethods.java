package Model;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Utility methods for working with timestamps and durations.
 * <p>
 * This class provides:
 * <ul>
 *   <li>Helpers to obtain the current time as a {@link java.sql.Timestamp}.</li>
 *   <li>Conversions between {@link Timestamp} and string representations.</li>
 *   <li>Convenience methods to compute durations in milliseconds from
 *       days/hours/minutes/seconds.</li>
 * </ul>
 * In the Kerberos demo, these methods are used to:
 * <ul>
 *   <li>Generate timestamps for tickets and authenticators.</li>
 *   <li>Compute requested lifetimes on the client side.</li>
 *   <li>Validate ticket lifetimes on the TGS/server side.</li>
 * </ul>
 */
public class TimeMethods {

    /**
     * @return current timestamp based on {@link Instant#now()}
     */
    public static Timestamp timeSignature(){
        return Timestamp.from(Instant.now());
    }

    /**
     * @return current timestamp as a string using {@link Timestamp#toString()}
     */
    public static String timeSignatureInString() {
        return timeSignature().toString();
    }

    /**
     * Converts a {@link Timestamp} to an ISO-8601 date-time string.
     *
     * @param timestamp timestamp to convert
     * @return ISO-8601 string representation of the timestamp
     */
    public static String timeStamp2String(Timestamp timestamp) {
        return DateTimeFormatter.ISO_DATE_TIME.format(timestamp.toLocalDateTime());
    }

    /**
     * Parses a string produced by {@link Timestamp#toString()} back into a {@link Timestamp}.
     *
     * @param timeStampValue timestamp string
     * @return {@link Timestamp} instance
     */
    public static Timestamp string2TimeStamp(String timeStampValue) {
        return Timestamp.valueOf(timeStampValue);
    }

    /**
     * Computes the number of milliseconds corresponding to the given duration.
     *
     * @param days    number of days
     * @param hours   number of hours
     * @param minutes number of minutes
     * @param seconds number of seconds
     * @return total duration in milliseconds
     */
    public static Long getMillis(int days, int hours, int minutes, int seconds) {
        return getMillis((days * 24) + hours, minutes, seconds);
    }

    /**
     * Computes the number of milliseconds corresponding to the given duration.
     *
     * @param hours   number of hours
     * @param minutes number of minutes
     * @param seconds number of seconds
     * @return total duration in milliseconds
     */
    public static Long getMillis(int hours, int minutes, int seconds) {
        return getMillis((hours * 60) + minutes, seconds);
    }

    /**
     * Computes the number of milliseconds corresponding to the given duration.
     *
     * @param minutes number of minutes
     * @param seconds number of seconds
     * @return total duration in milliseconds
     */
    public static Long getMillis(int minutes, int seconds) {
        return getMillis((minutes * 60) + seconds);
    }

    /**
     * Computes the number of milliseconds corresponding to the given duration.
     *
     * @param seconds number of seconds
     * @return total duration in milliseconds
     */
    public static Long getMillis(int seconds) {
        return seconds * 1000L;
    }
}
