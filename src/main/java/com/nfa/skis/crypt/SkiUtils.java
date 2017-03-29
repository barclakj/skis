package com.nfa.skis.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 11/02/2017.
 */
public class SkiUtils {
    private static Logger log = Logger.getLogger(SkiUtils.class.getCanonicalName());

    private static Map<Integer, String> HASH_ALGS = new HashMap<Integer, String>();

    static {
        HASH_ALGS.put(128, "MD5");
        HASH_ALGS.put(256, "SHA-256");
    }

    public static byte[] b64decode(String encdata) {
        log.info("Attempting to decode: " + encdata);
        byte[] data = Base64.getDecoder().decode(encdata);
        return data;
    }

    public static String b64encode(byte[] data) {
        byte[] encdata = Base64.getEncoder().encode(data);
        return new String(encdata);
    }

    public static byte[] hash(byte[] data, int keySize) throws SkiException  {
        // String strDigest = null;
        byte[] digest = null;

        try {
            String alg = HASH_ALGS.get(keySize);
            if (alg==null) {
                log.log(Level.WARNING, "Cannot support a key size of " + keySize + " bits.");
                throw new SkiException("Cannot support a key size of " + keySize + " bits.");
            } else {
                MessageDigest md = MessageDigest.getInstance(alg);
                md.update(data); // Change this to "UTF-16" if needed
                digest = md.digest();
                // strDigest = b64encode(digest);
            }
        } catch (NoSuchAlgorithmException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        }

        return digest;
    }

}
