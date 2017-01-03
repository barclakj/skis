import com.nfa.skis.SkiController;
import com.nfa.skis.crypt.SkiCrypt;
import com.nfa.skis.crypt.SkiKeyGen;
import junit.framework.TestCase;

import java.util.Arrays;

/**
 * Created by barclakj on 26/12/2016.
 */
public class TestCrypt extends TestCase {

    public void testGrant() {
        try {
            int k = (int)(Math.random()*Integer.MAX_VALUE);
            String keyName = "SENSITIVE_DATA_KEY_" + k;
            String identity = "SYSTEM_X";
            SkiController sc = new SkiController();
            String tkn = sc.createToken(identity);
            System.out.println("tkn: " + tkn);

            String key = sc.createKey(keyName, null, tkn);
            System.out.println("New key: " + key);

            String otherTkn = sc.grantToIdentity("SYSTEM_Y", tkn);

            key = sc.retrieveKey(keyName, otherTkn);
            System.out.println("Retrieved key: " + key);
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testSetAndGetKey() {
        try {
            String keyValue="adnbuj67sat6a45ftsadt6E$%^8g";

            int k = (int)(Math.random()*Integer.MAX_VALUE);
            String keyName = "SENSITIVE_DATA_KEY_" + k;
            String identity = "SYSTEM_X";
            SkiController sc = new SkiController();
            String tkn = sc.createToken(identity);
            System.out.println("tkn: " + tkn);

            String key = sc.createKey(keyName, keyValue, tkn);
            System.out.println("New key: " + key);

            key = sc.retrieveKey(keyName, tkn);
            System.out.println("Retrieved key: " + key);
            assertTrue(key.equals(keyValue));
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testGetKey() {
        try {
            int k = (int)(Math.random()*Integer.MAX_VALUE);
            String keyName = "SENSITIVE_DATA_KEY_" + k;

            String identity = "SYSTEM_X";
            SkiController sc = new SkiController();
            String tkn = sc.createToken(identity);
            System.out.println("tkn: " + tkn);

            String key = sc.createKey(keyName, null, tkn);
            System.out.println("New key: " + key);

            key = sc.retrieveKey(keyName, tkn);
            System.out.println("Retrieved key: " + key);
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testCreateKey() {
        try {
            int k = (int)(Math.random()*Integer.MAX_VALUE);
            String keyName = "SENSITIVE_DATA_KEY_" + k;

            String identity = "SYSTEM_X";
            SkiController sc = new SkiController();
            String tkn = sc.createToken(identity);
            System.out.println("tkn: " + tkn);

            String key = sc.createKey(keyName, tkn);
            System.out.println("New key: " + key);
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testCreateToken() {
        try {
            String identity = "SYSTEM_X";
            SkiController sc = new SkiController();
            String tkn = sc.createToken(identity);
            System.out.println("tkn: " + tkn);
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }

    }


}
