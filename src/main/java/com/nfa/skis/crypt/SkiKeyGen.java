package com.nfa.skis.crypt;

import com.nfa.skis.db.SkiDAO;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * Created by barclakj on 26/12/2016.
 */
public class SkiKeyGen {
    public static Logger log = Logger.getLogger(SkiKeyGen.class.getCanonicalName());

    private static int KEY_SIZE_BYTES = 16;

    public static Key keyFromBytes(byte[] keyData) {
        byte[] key = Arrays.copyOf(keyData, KEY_SIZE_BYTES);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        return secretKeySpec;
    }

    public static String generateKey() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(System.currentTimeMillis() + (long)(Math.random()*Integer.MAX_VALUE));
        byte[] bytes = new byte[KEY_SIZE_BYTES];
        sr.nextBytes(bytes);
        String k = SkiCrypt.b64encode(bytes);
        return k;
    }


    /**
     * Returns a new combined key of the specified key with the system key.
     * @param key
     * @return
     */
    public static String getComboKey(String key, String systemKey) throws SkiException {
        String newKey = key + systemKey;
        newKey = SkiCrypt.hash(newKey.getBytes());
        return newKey;
    }
}
