package com.nfa.skis.servlet;

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.ServerProperties;
import org.springframework.context.annotation.Configuration;

import javax.ws.rs.ApplicationPath;
import java.util.logging.Logger;

/**
 * Created by barclakj on 29/10/2016.
 */
@Configuration
@ApplicationPath("/rest")
public class JerseyConfig extends ResourceConfig {
    private static Logger log = Logger.getLogger(JerseyConfig.class.getCanonicalName());

    static {
        log.info("Identified Jersey Config import...");
    }

    public JerseyConfig() {
        super();
        log.info("Started Jersey Config import...");
        property(ServerProperties.RESPONSE_SET_STATUS_OVER_SEND_ERROR, true);
        log.info("Registering KeyServlet class...");
        register(KeyServlet.class);
        log.info("Registering TokenServlet class...");
        register(TokenServlet.class);

    }
}
