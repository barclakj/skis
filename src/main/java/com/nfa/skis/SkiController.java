package com.nfa.skis;

import com.nfa.skis.crypt.*;
import com.nfa.skis.db.SkiDAO;
import com.nfa.skis.model.Token;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 27/12/2016.
 */
public class SkiController {
    public static Logger log = Logger.getLogger(SkiController.class.getCanonicalName());

    private static final String SYSTEM_KEY = "SYS_KEY";
    private static final String TOKEN_KEY = "TKN_KEY";
    public static String SERVER_KEY_VALUE = null;

    /**
     * Make sure we can initialise the system with the environment variable for SVR_KEY else bomb out.
     */
    static {
        SERVER_KEY_VALUE = System.getenv("SVR_KEY");
        if (SERVER_KEY_VALUE==null || "".equals(SERVER_KEY_VALUE.trim())) {
            log.severe("Server key env variable not found (SVR_KEY). Ensure this is set before running.");
        }
    }

    /**
     * Checks that the required system keys are present.
     * @throws InternalSkiException
     */
    public void verify() throws InternalSkiException {
        if (SERVER_KEY_VALUE==null || "".equals(SERVER_KEY_VALUE.trim())) {
            throw new InternalSkiException("Cannot validate server key!");
        }

        String tokenKey = getTokenKey();
        String systemKey = getSystemKey();

        if (tokenKey==null || systemKey==null) {
            throw new InternalSkiException("Cannot validate token or system keys!");
        }
    }

    /**
     * Utility method to obtain the token key.
     * @return
     * @throws InternalSkiException
     */
    private String getTokenKey() throws InternalSkiException {
        String tknKey;
        SkiDAO dao = new SkiDAO();
        tknKey = dao.lookupSystemKey(TOKEN_KEY);
        if (tknKey==null) {
            tknKey = SkiKeyGen.generateKey();
            byte[] encryptedKey = SkiCrypt.encrypt(tknKey.getBytes(), SERVER_KEY_VALUE);
            String encKeyB64 = SkiCrypt.b64encode(encryptedKey);
            log.severe("NEW TOKEN KEY - RECORD THIS VALUE: " + encKeyB64);
            dao.saveSystemKey(TOKEN_KEY, encKeyB64);
        } else {
            byte[] decryptedKey = SkiCrypt.decrypt(SkiCrypt.b64decode(tknKey), SERVER_KEY_VALUE);
            tknKey = new String(decryptedKey);
        }
        return tknKey;
    }

    /**
     * Utility method to obatin the system key.
     * @return
     * @throws InternalSkiException
     */
    private String getSystemKey() throws InternalSkiException {
        String sysKey;
        SkiDAO dao = new SkiDAO();
        sysKey = dao.lookupSystemKey(SYSTEM_KEY);
        if (sysKey==null) {
            sysKey = SkiKeyGen.generateKey();
            byte[] encryptedKey = SkiCrypt.encrypt(sysKey.getBytes(), SERVER_KEY_VALUE);
            String encKeyB64 = SkiCrypt.b64encode(encryptedKey);
            log.severe("NEW SYSTEM KEY - RECORD THIS VALUE [ROOT KEY!!!]: " + encKeyB64);
            dao.saveSystemKey( SYSTEM_KEY, encKeyB64);
        } else {
            byte[] decryptedKey = SkiCrypt.decrypt(SkiCrypt.b64decode(sysKey), SERVER_KEY_VALUE);
            sysKey = new String(decryptedKey);
        }
        return sysKey;
    }

    /**
     * Creates a new token using the specified identity.
     * @param identity
     * @return
     * @throws InternalSkiException
     */
    public String createToken(String identity) throws InternalSkiException {
        String tokenKey = getTokenKey();
        String newKey = SkiKeyGen.generateKey();

        Token tkn = new Token();
        tkn.setIdentity(identity);
        tkn.setKey(newKey);
        // log.info("New token key: " + tkn.getKey());

        String tknValue = TokenHandler.encodeToken(tkn, tokenKey);
        if (tknValue==null) {
            log.warning("Failed to encode token during token creation!");
        }
        if (log.isLoggable(Level.FINE)) {
            log.fine("Created token with value: " + tknValue);
        }
        return tknValue;
    }

    /**
     * Grants access to the token key included in the specified token.
     * @param identity
     * @param tkn
     * @return
     * @throws InternalSkiException
     */
    public String grantToIdentity(String identity, String tkn) throws InternalSkiException {
        String tokenKey =  getTokenKey();
        Token otherTkn = TokenHandler.decodeToken(tkn, tokenKey);

        Token newTkn = new Token();
        newTkn.setIdentity(identity);
        newTkn.setKey(otherTkn.getKey());
        // log.info("New granted key: " + newTkn.getKey());

        String tknValue = TokenHandler.encodeToken(newTkn, tokenKey);
        if (tknValue==null) {
            log.warning("Failed to encode token during identity grant!");
        }
        if (log.isLoggable(Level.FINE)) {
            log.fine("Created token with value: " + tknValue);
        }
        return tknValue;
    }

    /**
     * Adds the specified identity to the blacklist so that this cannot be used to retrieve keys again.
     * Root key must be that created (see output on initialisation).
     * @param identity
     * @param rootKey
     * @return
     */
    public boolean revokeIdentity(String identity, String rootKey) throws InternalSkiException {
        String systemKey = getSystemKey();
        SkiDAO skiDao = new SkiDAO();

        byte[] decryptedKey = SkiCrypt.decrypt(SkiCrypt.b64decode(rootKey), SERVER_KEY_VALUE);
        String decRootKey = new String(decryptedKey);

        if (decRootKey.equals(systemKey)) {
            int upd = skiDao.blacklistIdentity(identity);
            if (upd>0) {
                log.info("Blacklisted identity: " + identity);
                return true;
            } else {
                log.severe("Failed to blacklist identity successfully! Identity: " + identity);
                throw new InternalSkiException("Failed to blacklist identity - check logs!");
            }
        } else {
            log.warning("Failed to blacklist identity due to invalid root key! Identity: " + identity);
            return false;
        }
    }

    /**
     * Utility method where key value is null and will be generated.
     * @param keyName
     * @param token
     * @return
     * @throws InternalSkiException
     */
    public String createKey(String keyName, String token) throws InternalSkiException {
        return createKey(keyName, null, token);
    }

    /**
     * Using the specified token, creates a new key with the given name and returns the value of the key (base64 encoded) for use by clients. Key value may
     * also be specified in the request.
     * Note that the stored key is encrypted using a hashed combination of the key provided in the token supplied along with the internal system key.
     * If the token used to create the key is lost and no others have been granted access then the key will be lost and cannot be retrieved.
     * If the key cannot be created then a null response will be returned. No further explanation is provided and clients will be told "access denied".
     * Only an internal database error will result in an internal server error.
     * @param keyName
     * @param keyValue
     * @param token
     * @return
     */
    public String createKey(String keyName, String keyValue, String token) throws InternalSkiException {
        String newKey;
        String systemKey =  getSystemKey();
        String tokenKey =  getTokenKey();
        SkiDAO skiDao = new SkiDAO();

        Token tkn = TokenHandler.decodeToken(token, tokenKey);
        if (tkn!=null) {
            try {
                String comboKey = SkiKeyGen.getComboKey(tkn.getKey(), systemKey);

                newKey = keyValue;
                if (newKey==null || "".equalsIgnoreCase(newKey.trim())) {
                    newKey = SkiKeyGen.generateKey();
                }

                byte[] encryptedKey = SkiCrypt.encrypt(newKey.getBytes(), comboKey);
                String strEncryptedKey = SkiCrypt.b64encode(encryptedKey);
                int saved = skiDao.saveKeyPair(keyName, strEncryptedKey);
                if (saved!=1) {
                    throw new InternalSkiException("Failed to save key pair to database! Check logs...");
                }
            } catch (SkiException e) {
                log.warning("Unable to create new key. Access denied. Check logs for error: " + e.getMessage());
                log.log(Level.WARNING, e.getMessage(), e);
                newKey = null;
            }
        } else {
            log.warning("Unable to decode token during key creation!  Access denied.");
            newKey = null;
        }
        return newKey;
    }

    /**
     * Retrieves key by name using the token specified. Token must be valid, not blacklisted and must contain the key part to unlock the key itself.
     * @param keyName
     * @param token
     * @return
     * @throws InternalSkiException
     */
    public String retrieveKey(String keyName, String token) throws InternalSkiException {
        String retKey;
        String systemKey =  getSystemKey();
        String tokenKey =  getTokenKey();
        SkiDAO skiDao = new SkiDAO();
        Token tkn = TokenHandler.decodeToken(token, tokenKey);
        if (tkn!=null) {
            boolean bl = skiDao.checkBlacklist(tkn.getIdentity());
            if (!bl) {
                try {
                    String comboKey = SkiKeyGen.getComboKey(tkn.getKey(), systemKey);

                    String encComboKey = skiDao.fetchKey(keyName);

                    byte[] encKey = SkiCrypt.b64decode(encComboKey);
                    byte[] decryptedKey = SkiCrypt.decrypt(encKey, comboKey);

                    retKey = new String(decryptedKey);
                } catch (SkiException e) {
                    log.warning("Unable to retrieve key.  Access denied. Check logs for error: " + e.getMessage());
                    log.log(Level.WARNING, e.getMessage(), e);
                    retKey = null;
                }
            } else {
                log.warning("Access denied. Attempt to retrieve key from blacklisted identity: " + tkn.getIdentity());
                retKey = null;
            }
        } else {
            log.warning("Access denied. Unable to decode token during key creation!");
            retKey = null;
        }
        return retKey;
    }
}
