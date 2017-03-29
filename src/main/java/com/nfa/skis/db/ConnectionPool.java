package com.nfa.skis.db;

import org.apache.commons.dbcp2.BasicDataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 29/03/2017.
 */
public class ConnectionPool {
    private static Logger log = Logger.getLogger(ConnectionPool.class.getCanonicalName());
    private BasicDataSource connectionPool;
    private static int INITIAL_SIZE = 2;

    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (Exception e) {
            log.log(Level.SEVERE, "Fatal error initialising JDBC driver");
            log.log(Level.SEVERE, e.getMessage(), e);
            System.exit(-1);
        }
    }

    public void initialize(String driver, String dbPath, String username, String passwd) {
        log.info("Initializing connection pool");
        connectionPool = new BasicDataSource();
        // conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
        connectionPool.setUsername(username);
        connectionPool.setPassword(passwd);
        connectionPool.setDriverClassName(driver);
        connectionPool.setUrl(dbPath);
        connectionPool.setInitialSize(INITIAL_SIZE);
        connectionPool.setMaxWaitMillis(1000);
        connectionPool.setRemoveAbandonedTimeout(30);
        connectionPool.setRemoveAbandonedOnBorrow(true);
        connectionPool.setRemoveAbandonedOnMaintenance(true);
        connectionPool.setLogAbandoned(true);

        connectionPool.setMaxTotal(10);
    }

    public Connection getConnection() throws SQLException {
        log.fine("Fetching connection from pool...");
        Connection conn = connectionPool.getConnection();
        conn.setAutoCommit(true);
        return conn;
    }

}
