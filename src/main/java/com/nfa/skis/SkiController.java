package com.nfa.skis;

import com.nfa.skis.crypt.*;
import com.nfa.skis.db.ConnectionPool;
import com.nfa.skis.db.ISki;
import com.nfa.skis.db.SkiDAO;
import com.nfa.skis.db.gcloud.GcloudSkiDAO;
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

    public static String DB_PATH = null;
    public static final int SQLITE_MODE = 0;
    public static final int GCLOUD_DATASTORE_MODE = 1;

    public static int MODE = GCLOUD_DATASTORE_MODE;

    private ICrypter crypter = new BasicJCECrypter();

    private TokenHandler th = new TokenHandler();

    /**
     * Make sure we can initialise the system with the environment variable for SVR_KEY else bomb out.
     */
    static {
        SERVER_KEY_VALUE = System.getenv("SVR_KEY");
        if (SERVER_KEY_VALUE==null || "".equals(SERVER_KEY_VALUE.trim())) {
            log.severe("Server key env variable not found (SVR_KEY). Ensure this is set before running.");
        }
    }

    public static void setSQLiteMode() {
        MODE = SQLITE_MODE;
    }

    public static void setGcloudDatastoreMode() {
        MODE = GCLOUD_DATASTORE_MODE;
    }

    private static ISki getSkiDao() {
        if (MODE==GCLOUD_DATASTORE_MODE)
            return new GcloudSkiDAO();
        else if (MODE==SQLITE_MODE) {
            SkiDAO skiDao = new SkiDAO();
            ConnectionPool pool = new ConnectionPool();
            pool.initialize("org.sqlite.JDBC", "jdbc:sqlite:" + SkiController.DB_PATH, null, null);
            skiDao.setConnectionPool(pool);
            return skiDao;
        } else {
            log.severe("Invalid database mode specified. Exiting. Mode is current set as: " + MODE);
            System.exit(-1);
            return null; // not that we should ever get here!
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

        byte[] tokenKey = getTokenKey();
        byte[] systemKey = getSystemKey();

        if (tokenKey==null || systemKey==null) {
            throw new InternalSkiException("Cannot validate token or system keys!");
        }
    }

    /**
     * Utility method to obtain the token key.
     * @return
     * @throws InternalSkiException
     */
    private byte[] getTokenKey() throws InternalSkiException {
        return sysKey(TOKEN_KEY);
    }

    private byte[] sysKey(String name) throws InternalSkiException {
        String tknKey;
        ISki dao = getSkiDao();
        byte[] decryptedKey = null;
        tknKey = dao.lookupSystemKey(name);
        if (tknKey==null) {
            decryptedKey = SkiKeyGen.generateKey(SkiKeyGen.DEFAULT_KEY_SIZE_BITS);
            byte[] encryptedKey = crypter.encrypt(decryptedKey, SkiUtils.b64decode(SERVER_KEY_VALUE));
            String encKeyB64 = SkiUtils.b64encode(encryptedKey);
            log.severe("NEW TOKEN KEY - RECORD THIS VALUE: " + encKeyB64);
            dao.saveSystemKey(name, encKeyB64);
        } else {
            decryptedKey = crypter.decrypt(SkiUtils.b64decode(tknKey), SkiUtils.b64decode(SERVER_KEY_VALUE));
        }
        return decryptedKey;
    }

    /**
     * Utility method to obatin the system key.
     * @return
     * @throws InternalSkiException
     */
    private byte[] getSystemKey() throws InternalSkiException {
        return sysKey(SYSTEM_KEY);
    }

    /**
     * Creates a new token using the specified identity.
     * @param identity
     * @return
     * @throws InternalSkiException
     */
    public String createToken(String identity) throws InternalSkiException {
        byte[] tokenKey = getTokenKey();
        byte[] newKey = SkiKeyGen.generateKey(SkiKeyGen.DEFAULT_KEY_SIZE_BITS);

        Token tkn = new Token();
        tkn.setIdentity(identity);
        tkn.setKey(newKey);
        // log.info("New token key: " + tkn.getKey());

        String tknValue = th.encodeToken(tkn, tokenKey);
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
        byte[] tokenKey =  getTokenKey();
        Token otherTkn = th.decodeToken(tkn, tokenKey);

        Token newTkn = new Token();
        newTkn.setIdentity(identity);
        newTkn.setKey(otherTkn.getKey());
        // log.info("New granted key: " + newTkn.getKey());

        String tknValue = th.encodeToken(newTkn, tokenKey);
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
        byte[] systemKey = getSystemKey();
        ISki skiDao = getSkiDao();

        byte[] decryptedKey = crypter.decrypt(SkiUtils.b64decode(rootKey), SkiUtils.b64decode(SERVER_KEY_VALUE));
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
    public byte[] createKey(String keyName, String token) throws InternalSkiException {
        return createKey(keyName, null, SkiKeyGen.DEFAULT_KEY_SIZE_BITS, token);
    }

    /**
     * Utility method where key value is null and will be generated.
     * @param keyName
     * @param token
     * @return
     * @throws InternalSkiException
     */
    public byte[] createKey(String keyName, int size, String token) throws InternalSkiException {
        return createKey(keyName, null, size, token);
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
    public byte[] createKey(String keyName, byte[] keyValue, int size, String token) throws InternalSkiException {
        byte[] newKey = null;
        byte[] systemKey =  getSystemKey();
        byte[] tokenKey =  getTokenKey();
        ISki skiDao = getSkiDao();

        Token tkn = th.decodeToken(token, tokenKey);
        if (tkn!=null) {
            try {
                byte[] comboKey = SkiKeyGen.getComboKey(tkn.getKey(), systemKey);

                if (keyValue!=null) {
                    newKey = keyValue;
                }
                if (newKey==null) {
                    newKey = SkiKeyGen.generateKey(size);
                }

                byte[] encryptedKey = crypter.encrypt(newKey, comboKey);
                String strEncryptedKey = SkiUtils.b64encode(encryptedKey);
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
    public byte[] retrieveKey(String keyName, String token) throws InternalSkiException {
        byte[] retKey;
        byte[] systemKey =  getSystemKey();
        byte[] tokenKey =  getTokenKey();
        ISki skiDao = getSkiDao();
        Token tkn = th.decodeToken(token, tokenKey);
        if (tkn!=null) {
            boolean bl = skiDao.checkBlacklist(tkn.getIdentity());
            if (!bl) {
                try {
                    byte[] comboKey = SkiKeyGen.getComboKey(tkn.getKey(), systemKey);

                    String encComboKey = skiDao.fetchKey(keyName);

                    if (encComboKey!=null) {

                        byte[] encKey = SkiUtils.b64decode(encComboKey);
                        byte[] decryptedKey = crypter.decrypt(encKey, comboKey);

                        retKey = decryptedKey;
                    } else {
                        log.warning("Unable to fetch key (is null) by name: " + keyName);
                        retKey = null;
                    }
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

    /**
     * Updates the key value to a new value and returns this value. Token must be valid for the current key for this operation to succeed.
     * Returns null if the key is not valid.
     * @param keyName
     * @param keyValue
     * @param size
     * @param token
     * @return
     * @throws InternalSkiException
     */
    public byte[] updateKey(String keyName, byte[] keyValue, int size, String token) throws InternalSkiException {
        byte[] newKey = null;
        byte[] systemKey =  getSystemKey();
        byte[] tokenKey =  getTokenKey();
        ISki skiDao = getSkiDao();

        byte[] oldkey = retrieveKey(keyName, token);
        if (oldkey!=null) {

            Token tkn = th.decodeToken(token, tokenKey);
            if (tkn != null) {
                try {
                    byte[] comboKey = SkiKeyGen.getComboKey(tkn.getKey(), systemKey);

                    if (keyValue != null) {
                        newKey = keyValue;
                    }
                    if (newKey == null) {
                        newKey = SkiKeyGen.generateKey(size);
                    }

                    byte[] encryptedKey = crypter.encrypt(newKey, comboKey);
                    String strEncryptedKey = SkiUtils.b64encode(encryptedKey);
                    int saved = skiDao.updateKeyPair(keyName, strEncryptedKey);
                    if (saved != 1) {
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
        } else {
            // token not valud.. access denied
            log.warning("Token now valid for key. Access denied.");
            newKey = null;
        }
        return newKey;
    }
}
