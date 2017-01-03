package com.nfa.skis.crypt;

import com.nfa.skis.model.Token;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 26/12/2016.
 */
public class TokenHandler {
    public static Logger log = Logger.getLogger(TokenHandler.class.getCanonicalName());

    private static final String DELIM_CHAR = ":";

    public static Token decodeToken(String tkn, String key) {
        Token token = null;
        byte[] keyData = SkiCrypt.b64decode(tkn);
        try {
            byte[] dec = SkiCrypt.decrypt(keyData, key);
            String val = new String(dec);
            String identity = val.substring(0, val.indexOf(DELIM_CHAR));
            String tknKey = val.substring(val.indexOf(DELIM_CHAR) + DELIM_CHAR.length());
            token = new Token();
            token.setKey(tknKey);
            token.setIdentity(identity);
        } catch (SkiException e) {
            log.warning("Unable to decode token");
            log.log(Level.WARNING, e.getMessage(), e);
            token = null;
        }
        return token;
    }

    public static String encodeToken(Token tkn, String key) {
        String encString = null;
        byte[] fullval = (tkn.getIdentity() + DELIM_CHAR + tkn.getKey()).getBytes();
        try {
            byte[] enc = SkiCrypt.encrypt(fullval, key);
            encString = SkiCrypt.b64encode(enc);
        } catch (SkiException e) {
            log.warning("Unable to encode token");
            log.log(Level.WARNING, e.getMessage(), e);
        }

        return encString;
    }
}
