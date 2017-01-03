import com.nfa.skis.crypt.SkiCrypt;
import com.nfa.skis.crypt.SkiKeyGen;
import junit.framework.TestCase;

/**
 * Created by barclakj on 27/12/2016.
 */
public class TestCoreCrypt extends TestCase {

    public void testA() {
        try {
            String encKey = SkiKeyGen.generateKey();
            System.out.println("Encrypted key: " + encKey);

            String txt = "This is a simple test but what do you think";

            System.out.println("Input data: " + new String(txt));

            byte[] encData = SkiCrypt.encrypt(txt.getBytes(), encKey);
            String encString = new String(SkiCrypt.b64encode(encData));

            System.out.println("Encrypted data: " + encString);
            System.out.println("Encrypted data string: " + new String(encData));

            byte[] decData = SkiCrypt.decrypt(encData, encKey);

            System.out.println("Decrypted data: " + new String(decData));
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testB() {
        try {
            String keyA = SkiKeyGen.generateKey();
            String keyB = SkiKeyGen.generateKey();

            String newKey = keyA + keyB;

            // newKey = new String(Arrays.copyOf(SkiCrypt.hash(newKey.getBytes()).getBytes(), 20));
            newKey = SkiCrypt.hash(newKey.getBytes());

            System.out.println("Encrypted key: " + newKey);

            String txt = "This is a simple test but what do you think";

            System.out.println("Input data: " + new String(txt));

            byte[] encData = SkiCrypt.encrypt(txt.getBytes(), newKey);
            String encString = new String(SkiCrypt.b64encode(encData));

            System.out.println("Encrypted data: " + encString);
            System.out.println("Encrypted data string: " + new String(encData));

            byte[] decData = SkiCrypt.decrypt(encData, newKey);

            System.out.println("Decrypted data: " + new String(decData));
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }
}
