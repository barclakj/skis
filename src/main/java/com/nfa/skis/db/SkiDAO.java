package com.nfa.skis.db;

import com.nfa.skis.crypt.InternalSkiException;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 26/12/2016.
 */
public class SkiDAO implements ISki {
    public static Logger log = Logger.getLogger(SkiDAO.class.getCanonicalName());

    private ConnectionPool pool = null;

    public void setConnectionPool(ConnectionPool cp) {
        this.pool = cp;
    }

    public boolean checkBlacklist(String identity) throws InternalSkiException {
        boolean bool = false;
        Connection conn = null;
        try {
            conn = pool.getConnection();
            bool = checkBlacklist(conn, identity);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
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
        Connection conn = null;
        try {
            conn = pool.getConnection();
            rval = blacklistIdentity(conn, identity);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
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
        Connection conn = null;
        try {
            conn = pool.getConnection();
            rval = saveKeyPair(conn, keyName, keyValue);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
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

    public int updateKeyPair(String keyName, String keyValue) throws InternalSkiException {
        int rval;
        Connection conn = null;
        try {
            conn = pool.getConnection();
            rval = updateKeyPair(conn, keyName, keyValue);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
        }
        return rval;
    }

    private static int updateKeyPair(Connection conn, String keyName, String keyValue) throws InternalSkiException {
        int rows = 0;
        PreparedStatement stmt = null;

        try {
            stmt = conn.prepareStatement("UPDATE KEYS SET KEY_VALUE=? WHERE KEY_NAME=?");
            stmt.clearParameters();
            stmt.setString(1, keyValue);
            stmt.setString(2, keyName);
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
        Connection conn = null;
        try {
            conn = pool.getConnection();
            rval = fetchKey(conn, keyName);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
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
        Connection conn = null;
        try {
            conn = pool.getConnection();
            rval = saveSystemKey(conn, keyName, keyValue);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
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
        Connection conn = null;
        try {
            conn = pool.getConnection();
            rval = lookupSystemKey(conn, keyName);
        } catch (SQLException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            throw new InternalSkiException(e);
        } finally {
            if (conn!=null) {
                try {
                    conn.close();
                } catch (SQLException e) { }
            }
            conn = null;
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
