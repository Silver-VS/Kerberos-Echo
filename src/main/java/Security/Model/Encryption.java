package Security.Model;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Utility class for symmetric and asymmetric encryption operations used in the Kerberos demo.
 * <p>
 * This class provides convenience methods to:
 * <ul>
 *   <li>Encrypt/decrypt arbitrary strings using a preconfigured {@link Cipher}.</li>
 *   <li>Encrypt a string with an RSA public key and decrypt it with an RSA private key.</li>
 *   <li>Encrypt/decrypt a string with a symmetric DES key.</li>
 * </ul>
 * <p>
 * Algorithms:
 * <ul>
 *   <li>Asymmetric: {@code RSA} via {@code Cipher.getInstance("RSA")}.</li>
 *   <li>Symmetric: {@code DES} via {@code Cipher.getInstance("DES")}.</li>
 * </ul>
 * The chosen algorithms are intentionally simple and intended for educational
 * purposes; they are not meant for production-grade security.
 */
public class Encryption {

    /**
     * Encrypts a UTF-8 string using the provided {@link Cipher} and returns the result as a Base64 string.
     *
     * @param encryptCipher initialized cipher in {@link Cipher#ENCRYPT_MODE}
     * @param toEncrypt     clear text string to encrypt
     * @return Base64-encoded ciphertext
     * @throws Exception if the encryption operation fails
     */
    public static String encrypt(Cipher encryptCipher, String toEncrypt) throws Exception {
        byte[] bytesToEncrypt = toEncrypt.getBytes(StandardCharsets.UTF_8);
        byte[] bytesEncrypted = encryptCipher.doFinal(bytesToEncrypt);
        bytesEncrypted = Base64.getEncoder().encode(bytesEncrypted);
        return new String(bytesEncrypted);
    }

    /**
     * Decrypts a Base64-encoded string using the provided {@link Cipher}.
     *
     * @param decryptCypher initialized cipher in {@link Cipher#DECRYPT_MODE}
     * @param toDecrypt     Base64-encoded ciphertext
     * @return decrypted clear text string (UTF-8)
     * @throws Exception if the decryption operation fails
     */
    public static String decrypt(Cipher decryptCypher, String toDecrypt) throws Exception {
        byte[] bytesToDecrypt = Base64.getDecoder().decode(toDecrypt.getBytes());
//        byte[] bytesToDecrypt = toDecrypt.getBytes();
        byte[] bytesDecrypted = decryptCypher.doFinal(bytesToDecrypt);
        return new String(bytesDecrypted);
    }

    /**
     * Encrypts a string using an RSA public key.
     * <p>
     * Internally this method obtains a {@code Cipher} instance for {@code "RSA"},
     * initializes it in encrypt mode with the provided {@code publicKey} and delegates
     * to {@link #encrypt(Cipher, String)}. The result is returned as Base64 text.
     *
     * @param publicKey RSA public key used for encryption
     * @param toEncrypt clear text string to encrypt
     * @return Base64-encoded ciphertext
     * @throws Exception if the encryption operation fails
     */
    public static String publicEncrypt(PublicKey publicKey, String toEncrypt) throws Exception {
        Cipher encryptCypher = Cipher.getInstance("RSA");
        encryptCypher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encrypt(encryptCypher, toEncrypt);
    }

    /**
     * Decrypts a string using an RSA private key.
     * <p>
     * Internally this method obtains a {@code Cipher} instance for {@code "RSA"},
     * initializes it in decrypt mode with the provided {@code privateKey} and
     * delegates to {@link #decrypt(Cipher, String)}.
     *
     * @param privateKey RSA private key used for decryption
     * @param toDecrypt  Base64-encoded ciphertext previously encrypted with the
     *                   corresponding public key
     * @return decrypted clear text string (UTF-8)
     * @throws Exception if the decryption operation fails
     */
    public static String privateDecrypt(PrivateKey privateKey, String toDecrypt) throws Exception {
        Cipher decryptCypher = Cipher.getInstance("RSA");
        decryptCypher.init(Cipher.DECRYPT_MODE, privateKey);
        return decrypt(decryptCypher, toDecrypt);
    }

    /**
     * Encrypts a string using a symmetric DES key.
     * <p>
     * Internally this method obtains a {@code Cipher} instance for {@code "DES"},
     * initializes it in encrypt mode with the provided {@code secretKey} and
     * delegates to {@link #encrypt(Cipher, String)}.
     *
     * @param secretKey symmetric DES key
     * @param toEncrypt clear text string to encrypt
     * @return Base64-encoded ciphertext
     * @throws Exception if the encryption operation fails
     */
    public static String symmetricEncrypt(SecretKey secretKey, String toEncrypt) throws Exception {
        Cipher encryptCypher = Cipher.getInstance("DES");
        encryptCypher.init(Cipher.ENCRYPT_MODE, secretKey);
        return encrypt(encryptCypher, toEncrypt);
    }

    /**
     * Decrypts a string using a symmetric DES key.
     * <p>
     * Internally this method obtains a {@code Cipher} instance for {@code "DES"},
     * initializes it in decrypt mode with the provided {@code secretKey} and
     * delegates to {@link #decrypt(Cipher, String)}.
     *
     * @param secretKey symmetric DES key
     * @param toDecrypt Base64-encoded ciphertext to decrypt
     * @return decrypted clear text string (UTF-8)
     * @throws Exception if the decryption operation fails
     */
    public static String symmetricDecrypt(SecretKey secretKey, String toDecrypt) throws Exception {
        Cipher decryptCypher = Cipher.getInstance("DES");
        decryptCypher.init(Cipher.DECRYPT_MODE, secretKey);
        return decrypt(decryptCypher, toDecrypt);
    }
}
