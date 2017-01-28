import com.nfa.skis.crypt.SkiCrypt;
import com.nfa.skis.crypt.SkiKeyGen;
import com.nfa.skis.db.ISki;
import com.nfa.skis.db.gcloud.GcloudSkiDAO;
import junit.framework.TestCase;

/**
 * Created by barclakj on 27/12/2016.
 */
public class TestDatastore extends TestCase {

    public void testCreateBlacklist() {
        try {
            GcloudSkiDAO sd = new GcloudSkiDAO();
            sd.blacklistIdentity("bob");
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

    public void testCreateKey() {
        try {
            ISki sd = new GcloudSkiDAO();
            String name = "TEST_KEY_NAME";
            String value = "TEST_KEY_VALUE";
            String newValue = "TEST_KEY_VALUE_NEW";

            sd.saveKeyPair(name, value);

            String foundValue = sd.fetchKey(name);
            if (!foundValue.equals(value)) {
                System.out.println("Retrieved key value is not equal to expected value on create: '" + value + "!=" + foundValue + "'");
                assertTrue(false);
            }

            sd.updateKeyPair(name, newValue);

            foundValue = sd.fetchKey(name);
            if (!foundValue.equals(newValue)) {
                System.out.println("Retrieved key value is not equal to expected value on update: '" + newValue + "!=" + foundValue + "'");
                assertTrue(false);
            }

        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

}
