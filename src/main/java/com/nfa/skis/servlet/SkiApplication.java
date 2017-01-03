package com.nfa.skis.servlet;

import org.springframework.stereotype.Component;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.logging.Logger;

/**
 * Created by barclakj on 26/07/2014.
 */

@Component
@ApplicationPath("/rest")
public class SkiApplication extends Application {
    private static Logger log = Logger.getLogger(SkiApplication.class.getCanonicalName());

    static {
        log.info("Initializing SkiApplication");
    }
}
