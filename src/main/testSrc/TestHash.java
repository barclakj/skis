import com.nfa.skis.crypt.SkiException;
import com.nfa.skis.crypt.SkiKeyGen;
import junit.framework.TestCase;

/**
 * Created by barclakj on 29/03/2017.
 */
public class TestHash extends TestCase {

    public void testHash() {
        String a = "gsahkdgakjdbakjsdnadsjsadasdsasd";
        String b = "gsahkadsadasdsad312312dgakjdbakjsdndddadsjsadasdsasd";

        try {
            byte[] newKey = SkiKeyGen.getComboKey(a.getBytes(), b.getBytes());

            System.out.println(newKey);
        } catch (SkiException e) {
            e.printStackTrace();
        }
    }
}
