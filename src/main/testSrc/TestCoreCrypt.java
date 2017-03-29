import com.nfa.skis.crypt.*;
import junit.framework.TestCase;

/**
 * Created by barclakj on 27/12/2016.
 */
public class TestCoreCrypt extends TestCase {

    public void testA() {
        try {
            ICrypter crypt = new BasicJCECrypter();
            byte[] encKey = SkiKeyGen.generateKey(128);
            System.out.println("Encrypted key: " + encKey);

            String txt = "This is a simple test but what do you think";

            System.out.println("Input data: " + new String(txt));

            byte[] encData = crypt.encrypt(txt.getBytes(), encKey);
            String encString = new String(SkiUtils.b64encode(encData));

            System.out.println("Encrypted data: " + encString);
            System.out.println("Encrypted data string: " + new String(encData));

            byte[] decData = crypt.decrypt(encData, encKey);

            System.out.println("Decrypted data: " + new String(decData));
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testB() {
        try {
            ICrypter crypt = new BasicJCECrypter();
            byte[] keyA = SkiKeyGen.generateKey(128);
            byte[] keyB = SkiKeyGen.generateKey(128);

            String newKey = new String(keyA) + new String(keyB);

            // newKey = new String(Arrays.copyOf(SkiCrypt.hash(newKey.getBytes()).getBytes(), 20));
            byte[] newByteKey = SkiUtils.hash(newKey.getBytes(), 128);

            System.out.println("Encrypted key: " + newByteKey);

            String txt = "This is a simple test but what do you think";

            System.out.println("Input data: " + new String(txt));

            byte[] encData = crypt.encrypt(txt.getBytes(), newByteKey);
            String encString = new String(SkiUtils.b64encode(encData));

            System.out.println("Encrypted data: " + encString);
            System.out.println("Encrypted data string: " + new String(encData));

            byte[] decData = crypt.decrypt(encData, newKey.getBytes());

            System.out.println("Decrypted data: " + new String(decData));
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }
}
