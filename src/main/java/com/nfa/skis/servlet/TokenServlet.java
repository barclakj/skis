package com.nfa.skis.servlet;

import com.nfa.skis.SkiController;
import com.nfa.skis.crypt.InternalSkiException;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 27/12/2016.
 */
@Component
@Path("tokens")
public class TokenServlet {
    private static Logger log = Logger.getLogger(TokenServlet.class.getCanonicalName());

    static {
        log.info("Initialising SkiServlet");
    }
    public static final String CREATE_OUTCOME = "CREATED";
    public static final String REVOKED_OUTCOME = "REVOKED";
    public static final String GRANT_OUTCOME = "GRANTED";


    @POST
    @Path("/{identity}")
    @Produces(MediaType.APPLICATION_JSON)
    public String createToken(@PathParam("identity") String identity,
                         @Context final HttpServletResponse response,
                         @Context final HttpServletRequest request) throws IOException {
        String tkn = null;

        SkiController sc = new SkiController();
        try {
            if (identity!=null) {
                tkn = sc.createToken(identity);
                JSONObject jo = new JSONObject();
                jo.put("token", tkn);
                jo.put("identity", identity);
                jo.put("action", CREATE_OUTCOME);

                tkn = jo.toString();
            } else {
                response.sendError(400);
            }
        } catch (InternalSkiException e) {
            log.log(Level.WARNING, "InternalSkiException on creating token: " + e.getMessage(), e);
            response.sendError(500);
        } catch (JSONException e) {
            log.log(Level.WARNING, "JSONException on creating token: " + e.getMessage(), e);
            response.sendError(500);
        }

        return tkn;
    }

    @POST
    @Path("/{identity}/grant")
    @Produces(MediaType.APPLICATION_JSON)
    public String grantToken(@PathParam("identity") String identity,
                              @Context final HttpServletResponse response,
                              @Context final HttpServletRequest request) throws IOException {
        String result = null;
        String token = null;

        Enumeration<String> tkns = request.getHeaders(KeyServlet.TOKEN_HEAD);
        if (tkns.hasMoreElements()) {
            token = tkns.nextElement();
        }

        SkiController sc = new SkiController();
        try {
            if (identity!=null) {
                String tkn = sc.grantToIdentity(identity, token);
                if (tkn!=null) {
                    JSONObject jo = new JSONObject();
                    jo.put("token", tkn);
                    jo.put("identity", identity);
                    jo.put("action", GRANT_OUTCOME);
                    result = jo.toString();
                } else {
                    log.log(Level.WARNING, "Failed attempt to grant token to identity: " + identity);
                    response.sendError(403);
                }
            } else {
                log.log(Level.WARNING, "Failed attempt to grant token to null identity: " + identity);
                response.sendError(400);
            }
        } catch (InternalSkiException e) {
            log.log(Level.WARNING, "InternalSkiException on granting token to identity: " + identity + " msg: " + e.getMessage(), e);
            response.sendError(500);
        } catch (JSONException e) {
            log.log(Level.WARNING, "JSONException on granting token to identity: " + identity + " msg: " + e.getMessage(), e);
            response.sendError(500);
        }

        return result;
    }

    @DELETE
    @Path("/{identity}")
    @Produces(MediaType.APPLICATION_JSON)
    public String revokeIdentity(@PathParam("identity") String identity,
                                 @Context final HttpServletResponse response,
                                 @Context final HttpServletRequest request) throws IOException {
        String result = null;
        String token = null;

        Enumeration<String> tkns = request.getHeaders(KeyServlet.TOKEN_HEAD);
        if (tkns.hasMoreElements()) {
            token = tkns.nextElement();
        }

        SkiController sc = new SkiController();
        try {
            if (identity!=null) {
                boolean success = sc.revokeIdentity(identity, token);
                if (success) {
                    JSONObject jo = new JSONObject();
                    jo.put("identity", identity);
                    jo.put("action", REVOKED_OUTCOME);
                    result = jo.toString();
                } else {
                    log.log(Level.WARNING, "Failed attempt to revoke identity: " + identity);
                    response.sendError(403);
                }
            } else {
                log.log(Level.WARNING, "Failed attempt to revoke null identity: " + identity);
                response.sendError(400);
            }
        } catch (InternalSkiException e) {
            log.log(Level.WARNING, "InternalSkiException on revoking identity: " + identity + " msg: " + e.getMessage(), e);
            response.sendError(500);
        } catch (JSONException e) {
            log.log(Level.WARNING, "JSONException on revoking identity: " + identity + " msg: " + e.getMessage(), e);
            response.sendError(500);
        }

        return result;
    }
}
