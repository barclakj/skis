package com.nfa.skis.db;

import com.nfa.skis.crypt.InternalSkiException;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 26/12/2016.
 */
public class SkiDAO {
    public static Logger log = Logger.getLogger(SkiDAO.class.getCanonicalName());

    public static String DB_PATH = null;

    private Connection conn;

    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (Exception e) {
            log.log(Level.SEVERE, "Fatal error initialising JDBC driver");
            log.log(Level.SEVERE, e.getMessage(), e);
            System.exit(-1);
        }
    }

    private void closeConnection() throws InternalSkiException {
        try {
            this.conn.close();
        } catch (SQLException e) {
            throw new InternalSkiException(e);
        }
    }

    private void initConnection() throws InternalSkiException {
        try {
            if (DB_PATH == null) {
                throw new InternalSkiException("No database path specified");
            }
            conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
            conn.setAutoCommit(true);
            if (log.isLoggable(Level.FINE)) {
                log.fine("Connected to: " + DB_PATH);
            }
        } catch (SQLException e) {
            conn = null;
            log.warning("Exception occurred during constructor(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        }
    }

    public boolean checkBlacklist(String identity) throws InternalSkiException {
        boolean bool = false;
        try {
            initConnection();
            bool = checkBlacklist(conn, identity);
        } finally {
            closeConnection();
        }
        return bool;
    }

    private static boolean checkBlacklist(Connection conn, String identity) throws InternalSkiException {
        boolean bl = false;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("SELECT 1 FROM IDENTITY_BLACKLIST WHERE IDENT=?");
            stmt.setString(1, identity);
            ResultSet rset = stmt.executeQuery();
            if (rset.next()) {
                bl = true;
            }
        } catch (SQLException e) {
            log.warning("Exception occurred during checkBlacklist(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            try {
                if (stmt!=null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.warning("Exception occurred during cleanup on checkBlacklist(...)");
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }
        return bl;
    }

    public int blacklistIdentity(String identity) throws InternalSkiException {
        int rval;
        try {
            initConnection();
            rval = blacklistIdentity(conn, identity);
        } finally {
            closeConnection();
        }
        return rval;
    }


    private static int blacklistIdentity(Connection conn, String identity) throws InternalSkiException {
        int rows = 0;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("INSERT INTO IDENTITY_BLACKLIST (IDENT) VALUES (?)");
            stmt.clearParameters();
            stmt.setString(1, identity);
            rows = stmt.executeUpdate();
        } catch (SQLException e) {
            log.warning("Exception occurred during blacklistIdentity(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            try {
                if (stmt!=null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.warning("Exception occurred during cleanup on blacklistIdentity(...)");
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }
        return rows;
    }

    public int saveKeyPair(String keyName, String keyValue) throws InternalSkiException {
        int rval;
        try {
            initConnection();
            rval = saveKeyPair(conn, keyName, keyValue);
        } finally {
            closeConnection();
        }
        return rval;
    }

    private static int saveKeyPair(Connection conn, String keyName, String keyValue) throws InternalSkiException {
        int rows = 0;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("INSERT INTO KEYS (KEY_NAME, KEY_VALUE) VALUES (?, ?)");
            stmt.clearParameters();
            stmt.setString(1, keyName);
            stmt.setString(2, keyValue);
            rows = stmt.executeUpdate();
        } catch (SQLException e) {
            log.warning("Exception occurred during saveSystemKey(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            try {
                if (stmt!=null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.warning("Exception occurred during cleanup on saveSystemKey(...)");
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }
        return rows;
    }

    public String fetchKey(String keyName) throws InternalSkiException {
        String rval;
        try {
            initConnection();
            rval = fetchKey(conn, keyName);
        } finally {
            closeConnection();
        }
        return rval;
    }

    private static String fetchKey(Connection conn, String keyName) throws InternalSkiException {
        String key = null;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("SELECT KEY_VALUE FROM KEYS WHERE KEY_NAME=?");
            stmt.setString(1, keyName);
            ResultSet rset = stmt.executeQuery();
            if (rset.next()) {
                key = rset.getString("KEY_VALUE");
            }
        } catch (SQLException e) {
            log.warning("Exception occurred during lookupSystemKey(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            try {
                if (stmt!=null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.warning("Exception occurred during cleanup on lookupSystemKey(...)");
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }

        return key;
    }

    public int saveSystemKey(String keyName, String keyValue) throws InternalSkiException {
        int rval;
        try {
            initConnection();
            rval = saveSystemKey(conn, keyName, keyValue);
        } finally {
            closeConnection();
        }
        return rval;
    }

    private static int saveSystemKey(Connection conn, String keyName, String keyValue) throws InternalSkiException {
        int rows = 0;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("INSERT INTO SYSTEM_KEYS (KEY_NAME, KEY_VALUE) VALUES (?, ?)");
            stmt.clearParameters();
            stmt.setString(1, keyName);
            stmt.setString(2, keyValue);
            rows = stmt.executeUpdate();
        } catch (SQLException e) {
            log.warning("Exception occurred during saveSystemKey(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            try {
                if (stmt!=null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.warning("Exception occurred during cleanup on saveSystemKey(...)");
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }
        return rows;
    }

    public String lookupSystemKey(String keyName) throws InternalSkiException {
        String rval;
        try {
            initConnection();
            rval = lookupSystemKey(conn, keyName);
        } finally {
            closeConnection();
        }
        return rval;
    }

    /**
     * Returns the system key value as specified by key name.
     * @param conn
     * @param keyName
     * @return
     * @throws InternalSkiException
     */
    private static String lookupSystemKey(Connection conn, String keyName) throws InternalSkiException {
        String key = null;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("SELECT KEY_VALUE FROM SYSTEM_KEYS WHERE KEY_NAME=?");
            stmt.setString(1, keyName);
            ResultSet rset = stmt.executeQuery();
            if (rset.next()) {
                key = rset.getString("KEY_VALUE");
            }
        } catch (SQLException e) {
            log.warning("Exception occurred during lookupSystemKey(...)");
            log.log(Level.WARNING, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            try {
                if (stmt!=null) {
                    stmt.close();
                }
            } catch (SQLException e) {
                log.warning("Exception occurred during cleanup on lookupSystemKey(...)");
                log.log(Level.WARNING, e.getMessage(), e);
            }
        }

        return key;
    }
}
