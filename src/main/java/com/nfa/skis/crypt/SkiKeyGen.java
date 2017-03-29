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

    public static final int DEFAULT_KEY_SIZE_BITS = 128;

    public static Key keyFromBytes(byte[] keyData) {
        byte[] key = Arrays.copyOf(keyData, DEFAULT_KEY_SIZE_BITS/8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        return secretKeySpec;
    }

    public static byte[] generateKey(int size) {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(System.currentTimeMillis() + (long)(Math.random()*Integer.MAX_VALUE));
        byte[] bytes = new byte[size/8];
        sr.nextBytes(bytes);
        // String k = SkiCrypt.b64encode(bytes);
        return bytes;
    }


    /**
     * Returns a new combined key of the specified key with the system key.
     * @param key
     * @return
     */
    public static byte[] getComboKey(byte[] key, byte[] systemKey) throws SkiException {
        String newKey = new String(key) + new String(systemKey);
        byte[] newKeyByte = SkiUtils.hash(newKey.getBytes(), DEFAULT_KEY_SIZE_BITS);
        log.info("Key size should be " + DEFAULT_KEY_SIZE_BITS + " and is " + (8*newKeyByte.length));
        return newKeyByte; // Arrays.copyOf(newKey.getBytes(), DEFAULT_KEY_SIZE_BITS/8);
    }
}
