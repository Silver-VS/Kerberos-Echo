package Security.Model;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Helper methods for creating, persisting and recovering cryptographic keys.
 * <p>
 * Responsibilities:
 * <ul>
 *   <li>Generate RSA key pairs and save them to disk.</li>
 *   <li>Generate symmetric DES keys and save them to disk.</li>
 *   <li>Recover public/private RSA keys and symmetric DES keys from files.</li>
 *   <li>Convert keys to/from string representations for transport.</li>
 * </ul>
 * The keys are stored as raw encoded bytes in {@code .key} files under the
 * {@code Security/SecretVault/Generated} and {@code Security/SecretVault/Connection}
 * directories.
 */
public class KeyMethods {

    /**
     * Generates an RSA key pair for the given actor and stores it under the
     * specified directory.
     * <p>
     * This method creates:
     * <ul>
     *   <li>{@code public<whoAreYou>.key}</li>
     *   <li>{@code private<whoAreYou>.key}</li>
     * </ul>
     * in the given {@code directoryPath}.
     *
     * @param directoryPath directory where the key files will be stored, ending with a path separator
     * @param whoAreYou     logical identifier of the actor (e.g. {@code "AS"}, {@code "Client"})
     * @throws Exception if key generation or file operations fail
     */
    public static void keyCreator(String directoryPath, String whoAreYou) throws Exception {

        String publicAddress = directoryPath + "public" + whoAreYou + ".key";
        String privateAddress = directoryPath + "private" + whoAreYou + ".key";

        KeyPairGenerator generatorRSA = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = generatorRSA.generateKeyPair();

        saveKey(keyPair.getPublic(), publicAddress);
        saveKey(keyPair.getPrivate(), privateAddress);
        System.out.println("Llave del " + whoAreYou + " fue creada exitosamente.");
    }

    /**
     * Saves the given key to a file under the specified directory, using a naming
     * convention based on the owner and whether it is public or private.
     * <p>
     * The resulting filename is:
     * {@code <directoryPath>/<kindOfKey><whoseKey>.key} where {@code kindOfKey}
     * is {@code "public"} or {@code "private"}.
     *
     * @param key         key to save
     * @param directoryPath directory to store the key file (ending with a path separator)
     * @param whoseKey    logical identifier of the owner (e.g. {@code "Client"}, {@code "AS"})
     * @param isPublic    {@code true} if the key is public, {@code false} if it is private
     * @throws Exception if file operations fail
     */
    public static void saveKey(Key key, String directoryPath, String whoseKey , boolean isPublic) throws Exception {
        String kindOfKey;
        if (isPublic) kindOfKey = "public"; else kindOfKey = "private";
        String address = directoryPath + kindOfKey + whoseKey + ".key";
        saveKey(key, address);
    }

    /**
     * Generates a new symmetric DES key.
     *
     * @return freshly generated {@link SecretKey} for DES
     * @throws Exception if the key generator cannot be created
     */
    public static SecretKey generateSecretKey() throws Exception{
        return KeyGenerator.getInstance("DES").generateKey();
    }

    public static void saveKey(Key key, String fileAddress) throws Exception{

        byte[] keyBytes = key.getEncoded();
        FileOutputStream stream = new FileOutputStream(fileAddress);
        stream.write(keyBytes);
        stream.close();
    }

    /**
     * Persists a symmetric secret key to disk.
     * <p>
     * The resulting filename is:
     * {@code <path>/Symmetric-<owner>-<withWho>.key}.
     *
     * @param key      symmetric key to save
     * @param path     directory path (ending with a path separator)
     * @param owner    logical name of the actor storing the key (e.g. {@code "AS"})
     * @param withWho  logical name of the other actor sharing the key (e.g. {@code "Client"})
     * @throws Exception if file operations fail
     */
    public static void saveSecret(SecretKey key, String path, String owner,String withWho) throws Exception {
        String fileAddress = path + "Symmetric-" + owner + "-" + withWho + ".key";
        saveKey(key, fileAddress);
    }

    /**
     * Recovers a stored RSA public or private key from disk and returns the
     * corresponding {@link KeySpec}.
     * <p>
     * File naming convention:
     * <ul>
     *   <li>Public: {@code <path>/public<whosKey>.key}</li>
     *   <li>Private: {@code <path>/private<whosKey>.key}</li>
     * </ul>
     *
     * @param isPublic {@code true} to load a public key, {@code false} for a private key
     * @param path     directory containing the key files (ending with a path separator)
     * @param whosKey  logical identifier of the key owner (e.g. {@code "AS"})
     * @return a {@link KeySpec} that can be turned into a {@link PublicKey} or {@link PrivateKey}
     * @throws Exception if file operations fail
     */
    public static KeySpec recoverKey(boolean isPublic, String path, String whosKey) throws Exception{

        String fileAddress;
        if (isPublic) fileAddress = path + "public";
        else fileAddress = path + "private";

        fileAddress = fileAddress + whosKey + ".key";

        byte[] bytes = readFromSomething(fileAddress);

        if (isPublic) return new X509EncodedKeySpec(bytes);
        else return new PKCS8EncodedKeySpec(bytes);
    }

    /**
     * Recovers a symmetric DES key from disk.
     * <p>
     * Looks for a file named:
     * {@code <path>/Symmetric-<whoAreYou>-<withWho>.key}.
     *
     * @param path      directory containing the symmetric key files (ending with a path separator)
     * @param whoAreYou logical name of the actor reading the key
     * @param withWho   logical name of the other actor sharing the key
     * @return the recovered {@link SecretKey}
     * @throws Exception if file operations fail
     */
    public static SecretKey recoverSecret(String path, String whoAreYou,String withWho) throws Exception {
        String fileAddress = path + "Symmetric-" + whoAreYou + "-" + withWho + ".key";
        byte[] bytes = readFromSomething(fileAddress);
        return new SecretKeySpec(bytes, "DES");
    }

    public static PrivateKey recoverPrivate(String path, String whosKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpecPrivate = recoverKey(false, path, whosKey);
        return keyFactory.generatePrivate(keySpecPrivate);
    }

    public static PublicKey recoverPublic(String path, String whosKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpecPublic = recoverKey(true, path, whosKey);
        return keyFactory.generatePublic(keySpecPublic);
    }

    /**
     * Converts any {@link Key} into a Base64-encoded string representation.
     * <p>
     * Useful for embedding keys inside tickets or sending them over the network.
     *
     * @param key key to convert
     * @return Base64 representation of the key's encoded bytes
     */
    public static String convertAnyKey2String(Key key) {
        byte[] keyEncoded = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyEncoded);
    }

    /**
     * Converts a Base64-encoded string into an RSA {@link PublicKey}.
     *
     * @param keyInString Base64-encoded public key
     * @return RSA public key instance
     * @throws Exception if the key cannot be reconstructed
     */
    public static PublicKey convertString2Public(String keyInString) throws Exception{
        byte[] decodedKey = Base64.getDecoder().decode(keyInString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return  keyFactory.generatePublic(keySpec);
    }

    /**
     * Converts a Base64-encoded string into a symmetric DES {@link SecretKey}.
     *
     * @param keyInString Base64-encoded symmetric key
     * @return DES {@link SecretKey}
     */
    public static SecretKey convertString2Key(String keyInString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyInString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
    }

    /**
     * Utility method to read all bytes from a file.
     *
     * @param address file path
     * @return byte array with the file contents
     * @throws Exception if file operations fail
     */
    public static byte[] readFromSomething(String address) throws Exception{
        FileInputStream stream = new FileInputStream(address);
        byte[] bytes = new byte[stream.available()];
        stream.read(bytes);
        stream.close();
        return bytes;
    }
}
