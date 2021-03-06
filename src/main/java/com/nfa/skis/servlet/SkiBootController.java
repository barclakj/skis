package com.nfa.skis.servlet;

import com.nfa.skis.SkiController;
import com.nfa.skis.crypt.*;
import com.nfa.skis.db.SkiDAO;
import com.nfa.skis.db.gcloud.GcloudSkiDAO;
import org.apache.catalina.authenticator.jaspic.AuthConfigFactoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import javax.security.auth.message.config.AuthConfigFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 29/10/2016.
 */
@SpringBootApplication
public class SkiBootController extends SpringBootServletInitializer {
    private static Logger log = Logger.getLogger(SkiBootController.class.getCanonicalName());

    private @Autowired AutowireCapableBeanFactory beanFactory;

    public static void main(String[] args) throws Exception {
        boolean init = false;
        boolean ready = false;
        String act = null;
        if (args.length>0) {
            for(int i=0;i<args.length;i++) {
                if (args[i].startsWith("-db=")) {
                    SkiController.DB_PATH = args[i].substring(4);
                    SkiController.setSQLiteMode();
                    log.info("Database connection string set to: " + args[i].substring(4));
                    ready = true;
                }
                if (args[i].equalsIgnoreCase("-init")) {
                    init = true;
                }
                if (args[i].startsWith("-acct=")) {
                    act = args[i].substring(6);
                    ready = true;
                    log.info("Using acct: " + act);
                }
            }
        }
        if (act!=null) GcloudSkiDAO.setAcct(act);

        if (!ready) {
            System.err.println("Database (-db=<file.sqlite>) must be specified if using DB or acct if using GCloud. If initialising then use '-init' flag.");
            System.exit(-1);
        } else {
            if (init) {
                initSystem(args);
            } else {
                startSkiServer(args);
            }
        }
    }

    private static void startSkiServer(String[] args) {
        if (AuthConfigFactory.getFactory() == null) {
            AuthConfigFactory.setFactory(new AuthConfigFactoryImpl());
        }

        try {
            SkiController sc = new SkiController();
            sc.verify();
        } catch (InternalSkiException e) {
            log.log(Level.SEVERE, e.getMessage(), e);
            System.exit(-1);
        }

        ApplicationContext ctx = SpringApplication.run(SkiBootController.class, args);
        log.info(ctx.getApplicationName() + " application started!");
    }

    private static void initSystem(String[] args) {


        String svrKey = SkiUtils.b64encode( (SkiKeyGen.generateKey(SkiKeyGen.DEFAULT_KEY_SIZE_BITS)) );
        SkiController.SERVER_KEY_VALUE = svrKey;
        System.out.println("SERVER KEY - RECORD THIS VALUE AND USE AS ENV VAR 'SVR_KEY': " + svrKey);
        try {
            SkiController sc = new SkiController();
            sc.verify();
            log.info("Successfully verified installation.");
        } catch (InternalSkiException e) {
            log.log(Level.SEVERE, "Error initialising system. Does the database exist? Has it already been initialised? " + e.getMessage(), e);
            System.exit(-1);
        }
        System.exit(0);
    }

}
