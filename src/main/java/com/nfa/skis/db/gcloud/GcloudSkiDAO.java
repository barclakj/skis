package com.nfa.skis.db.gcloud;

import com.google.cloud.datastore.*;
import com.nfa.skis.crypt.InternalSkiException;
import com.nfa.skis.db.ISki;

import java.util.logging.Logger;

/**
 * Created by barclakj on 28/01/2017.
 */
public class GcloudSkiDAO implements ISki {
    private static Logger log = Logger.getLogger(GcloudSkiDAO.class.getCanonicalName());

    private static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    private static String ACCT = "DEFAULT";
    private static String BLACKLIST_KIND = ACCT + "_SKIS_BLACKLIST";
    private static String KEY_PAIR_KIND = ACCT + "_SKIS_KEY_PAIR";
    private static String SYSTEM_KEY_PAIR_KIND = ACCT + "_SKIS_SYSTEM_KEY_PAIR";

    public static void setAcct(String na) {
        ACCT = na.toUpperCase().trim();
        BLACKLIST_KIND = ACCT + "_SKIS_BLACKLIST";
        KEY_PAIR_KIND = ACCT + "_SKIS_KEY_PAIR";
        SYSTEM_KEY_PAIR_KIND = ACCT + "_SKIS_SYSTEM_KEY_PAIR";
    }

    public boolean checkBlacklist(String identity) throws InternalSkiException {
        log.info("Searching blacklist for " + identity);
        boolean found = false;
        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind(BLACKLIST_KIND)
                .setFilter(StructuredQuery.CompositeFilter.and(
                        StructuredQuery.PropertyFilter.eq("identity", identity)))
                .build();

        QueryResults<Entity> resultSet = datastore.run(query);
        if (resultSet.hasNext()) {
            log.info("Found blacklisted identity " + identity);
            found = true;
        } else {
            log.info("Identity not blacklisted: " + identity);
        }
        return found;
    }

    public int blacklistIdentity(String identity) throws InternalSkiException {
        log.info("Blacklisting: " + identity);
        if (!checkBlacklist(identity)) {
            KeyFactory keyFactory = datastore.newKeyFactory().setKind(BLACKLIST_KIND);
            Key key = datastore.allocateId(keyFactory.newKey());
            log.info("Created key: " + key.toUrlSafe());
            Entity item = Entity.newBuilder(key)
                    .set("identity", identity)
                    .build();
            Entity putItem = datastore.put(item);
            log.info("Created entity: " + putItem.getKey().getKind() + " with key " + putItem.getKey().toUrlSafe());
            if (putItem != null) {
                log.info("Created blacklist item");
                return 1;
            } else {
                log.warning("Failed to blacklist identity: " + identity);
                return 0;
            }
        } else {
            log.warning("Identity is already blacklisted! " + identity);
            return 0;
        }
    }

    public int saveKeyPair(String keyName, String keyValue) throws InternalSkiException {
        log.info("Saving keypair: " + keyName);
        if (fetchKey(keyName)==null) {
            KeyFactory keyFactory = datastore.newKeyFactory().setKind(KEY_PAIR_KIND);
            Key key = datastore.allocateId(keyFactory.newKey());
            log.info("Created key: " + key.toUrlSafe());
            Entity item = Entity.newBuilder(key)
                    .set("keyName", keyName)
                    .set("keyValue", keyValue)
                    .build();
            Entity putItem = datastore.put(item);
            log.info("Created entity: " + putItem.getKey().getKind() + " with key " + putItem.getKey().toUrlSafe());
            if (putItem != null) {
                log.info("Created key-pair item");
                return 1;
            } else {
                log.warning("Failed to create keypair: " + keyName);
                return 0;
            }
        } else {
            log.warning("Keypair already exists! " + keyName);
            return 0;
        }
    }

    public String fetchKey(String keyName) throws InternalSkiException {
        log.info("Searching keys for " + keyName);
        String value = null;
        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind(KEY_PAIR_KIND)
                .setFilter(StructuredQuery.CompositeFilter.and(
                        StructuredQuery.PropertyFilter.eq("keyName", keyName)))
                .build();

        QueryResults<Entity> resultSet = datastore.run(query);
        if (resultSet.hasNext()) {
            log.info("Found keyname " + keyName);
            value = resultSet.next().getString("keyValue");
        } else {
            value = null;
            log.info("Key not found: " + keyName);
        }
        return value;
    }

    public int updateKeyPair(String keyName, String keyValue) throws InternalSkiException {
        log.info("Searching keys for " + keyName);
        int value = 0;
        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind(KEY_PAIR_KIND)
                .setFilter(StructuredQuery.CompositeFilter.and(
                        StructuredQuery.PropertyFilter.eq("keyName", keyName)))
                .build();

        QueryResults<Entity> resultSet = datastore.run(query);
        if (resultSet.hasNext()) {
            log.info("Found keyname " + keyName);
            Key k = resultSet.next().getKey();
            Entity item = Entity.newBuilder(k)
                    .set("keyName", keyName)
                    .set("keyValue", keyValue)
                    .build();
            Entity putItem = datastore.put(item);
            log.info("Updated keyValue for " + keyName + " item: " + k.toUrlSafe());
            value = 1;
        } else {
            value = 0;
            log.info("Key not found: " + keyName);
        }
        return value;

    }

    public int saveSystemKey(String keyName, String keyValue) throws InternalSkiException {
        log.info("Saving system keypair: " + keyName);
        if (fetchKey(keyName)==null) {
            KeyFactory keyFactory = datastore.newKeyFactory().setKind(SYSTEM_KEY_PAIR_KIND);
            Key key = datastore.allocateId(keyFactory.newKey());
            log.info("Created system key: " + key.toUrlSafe());
            Entity item = Entity.newBuilder(key)
                    .set("keyName", keyName)
                    .set("keyValue", keyValue)
                    .build();
            Entity putItem = datastore.put(item);
            log.info("Created entity: " + putItem.getKey().getKind() + " with key " + putItem.getKey().toUrlSafe());
            if (putItem != null) {
                log.info("Created system key-pair item");
                return 1;
            } else {
                log.warning("Failed to create system keypair: " + keyName);
                return 0;
            }
        } else {
            log.warning("System keypair already exists! " + keyName);
            return 0;
        }
    }

    public String lookupSystemKey(String keyName) throws InternalSkiException {
        log.info("Searching system keys for " + keyName);
        String value = null;
        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind(SYSTEM_KEY_PAIR_KIND)
                .setFilter(StructuredQuery.CompositeFilter.and(
                        StructuredQuery.PropertyFilter.eq("keyName", keyName)))
                .build();

        QueryResults<Entity> resultSet = datastore.run(query);
        if (resultSet.hasNext()) {
            log.info("Found system keyname " + keyName);
            value = resultSet.next().getString("keyValue");
        } else {
            value = null;
            log.info("System key not found: " + keyName);
        }
        return value;
    }
}
