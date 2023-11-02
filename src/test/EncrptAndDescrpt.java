import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class EncrptAndDescrpt {

        public static void main(String[] args) throws Exception {
            final String secretKey = "";
            SecretKeySpec secretKeySpec = createSecretKey(secretKey);

            // Read original text from file and encrypt it
            String originalString = new String(Files.readAllBytes(Paths.get("plain.txt")));
            String encryptedString = encrypt(originalString, secretKeySpec);
            System.out.println("Encrypted string: " + encryptedString);

            // Write the encrypted string to a file
            Files.write(Paths.get("encrypted.txt"), encryptedString.getBytes());

            // Read encrypted text from file and decrypt it
            String encryptedTextFromFile = new String(Files.readAllBytes(Paths.get("encrypted.txt")));
            String decryptedString = decrypt(encryptedTextFromFile, secretKeySpec);
            System.out.println("Decrypted string: " + decryptedString);
        }

        private static SecretKeySpec createSecretKey(String secret) throws Exception {
            byte[] key = secret.getBytes(StandardCharsets.UTF_8);
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // use only first 128 bit

            return new SecretKeySpec(key, "AES");
        }

        public static String encrypt(String strToEncrypt, SecretKeySpec secretKey) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception e) {
                System.out.println("Error while encrypting: " + e.toString());
            }
            return null;
        }

        public static String decrypt(String strToDecrypt, SecretKeySpec secretKey) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
            } catch (Exception e) {
                System.out.println("Error while decrypting: " + e.toString());
            }
            return null;
        }
    }
