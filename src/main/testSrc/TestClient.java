import com.nfa.skis.client.SkiClient;
import com.nfa.skis.crypt.InternalSkiException;
import junit.framework.TestCase;

/**
 * Created by barclakj on 02/01/2017.
 */
public class TestClient extends TestCase {

    static {
        SkiClient.ROOT_URL = "http://192.168.0.4:9080/rest";
    }

    public void testCreateToken() {
        String identity = "dhajklasdnlk";

        SkiClient client = new SkiClient();
        try {
            String tkn = client.createToken(identity);
            assertNotNull(tkn);
        } catch (InternalSkiException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public void testCreateKey() {
        int k = (int)(Math.random()*Integer.MAX_VALUE);
        String keyName = "SENSITIVE_DATA_KEY_" + k;

        String identity = "dhajklasdnlk";

        SkiClient client = new SkiClient();

        try {
            String tkn = client.createToken(identity);
            assertNotNull(tkn);
            String key = client.createKey(keyName, tkn);
            assertNotNull(key);
            System.out.println("Successfully created key: " + key);

        } catch (InternalSkiException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public void testRetrieveKey() {
        int k = (int)(Math.random()*Integer.MAX_VALUE);
        String keyName = "SENSITIVE_DATA_KEY_" + k;

        String identity = "dhajklasdnlk";

        SkiClient client = new SkiClient();

        try {
            String tkn = client.createToken(identity);
            assertNotNull(tkn);
            String key = client.createKey(keyName, "rudolph", tkn);
            assertNotNull(key);
            assertEquals("rudolph", key);
            System.out.println("Successfully created key");

            key = client.getKey(keyName, tkn);
            assertNotNull(key);
            assertEquals("rudolph", key);
            System.out.println("Successfully retrieved key");

        } catch (InternalSkiException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public void testRevokeIdentity() {
        String identity = "revokedidentity";
        String rootToken = ""; // use system key from init..
        SkiClient client = new SkiClient();

        try {
            client.revokeIdentity(identity, rootToken);
            System.out.println("Successfully revoked identity");
        } catch (InternalSkiException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public void testRetrieveKeyNewToken() {
        int k = (int)(Math.random()*Integer.MAX_VALUE);
        String keyName = "SENSITIVE_DATA_KEY_" + k;

        String identity = "dhajklasdnlk";

        SkiClient client = new SkiClient();

        try {
            String tkn = client.createToken(identity);
            assertNotNull(tkn);
            String key = client.createKey(keyName, "santa", tkn);
            assertNotNull(key);
            assertEquals("santa", key);
            System.out.println("Successfully created key");

            String newtkn = client.grantToken("vampire", tkn);
            assertTrue(!tkn.equals(newtkn));

            key = client.getKey(keyName, newtkn);
            assertNotNull(key);
            assertEquals("santa", key);
            System.out.println("Successfully retrieved key using new token");

        } catch (InternalSkiException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
