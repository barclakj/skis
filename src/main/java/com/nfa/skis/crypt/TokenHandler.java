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

    private ICrypter crypter = new BasicJCECrypter();

    public Token decodeToken(String tkn, byte[] key) {
        Token token = null;
        byte[] keyData = SkiUtils.b64decode(tkn);
        try {
            byte[] dec = crypter.decrypt(keyData, key);
            String val = new String(dec);
            String identity = val.substring(0, val.indexOf(DELIM_CHAR));
            String tknKey = val.substring(val.indexOf(DELIM_CHAR) + DELIM_CHAR.length());

            token = new Token();
            token.setKey(SkiUtils.b64decode(tknKey));
            token.setIdentity(identity);
        } catch (SkiException e) {
            log.warning("Unable to decode token");
            log.log(Level.WARNING, e.getMessage(), e);
            token = null;
        }
        return token;
    }

    public String encodeToken(Token tkn, byte[] key) {
        String encString = null;
        String fullval = (tkn.getIdentity() + DELIM_CHAR + SkiUtils.b64encode(tkn.getKey()));
        byte[] fullbytes = fullval.getBytes();
        try {
            byte[] enc = crypter.encrypt(fullbytes, key);
            encString = SkiUtils.b64encode(enc);
        } catch (SkiException e) {
            log.warning("Unable to encode token");
            log.log(Level.WARNING, e.getMessage(), e);
        }

        return encString;
    }
}
