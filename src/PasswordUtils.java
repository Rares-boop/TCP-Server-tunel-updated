import java.security.SecureRandom;
import java.util.Base64;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class PasswordUtils {
    public static SecureRandom secureRandom =  new SecureRandom();
    public static void main(String[] args){
        System.out.println("DA");
        String password = "password3";
        String salt = generateSalt(50);
        String hashedPassword = hashPassword(password, salt);
        System.out.println("Salt "+salt);
        System.out.println("Hashed password "+hashedPassword);
        System.out.println("Verify hash "+verifyPassword(password, salt, hashedPassword));
    }
    public static String generateSalt(int length){
        byte[] salt = new byte[length];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashPassword(String password, String salt){
        Argon2 argon2 = Argon2Factory.create();
        return argon2.hash(3,65536,2,(password+salt).toCharArray());
    }

    public static boolean verifyPassword(String password, String salt, String hash){
        Argon2 argon2 =Argon2Factory.create();
        return argon2.verify(hash,(password+salt).toCharArray());
    }
}
