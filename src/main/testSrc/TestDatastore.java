import com.nfa.skis.crypt.SkiCrypt;
import com.nfa.skis.crypt.SkiKeyGen;
import com.nfa.skis.db.gcloud.GcloudSkiDAO;
import junit.framework.TestCase;

/**
 * Created by barclakj on 27/12/2016.
 */
public class TestDatastore extends TestCase {

    public void testA() {
        try {
            GcloudSkiDAO sd = new GcloudSkiDAO();
            sd.blacklistIdentity("bob");
        } catch (Throwable t) {
            t.printStackTrace();
            assertTrue(false);
        }
    }

}
