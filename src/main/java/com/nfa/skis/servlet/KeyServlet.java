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
@Path("keys")
public class KeyServlet {
    private static Logger log = Logger.getLogger(KeyServlet.class.getCanonicalName());

    public static final String TOKEN_HEAD = "X-SKI_TKN";

    static {
        log.info("Initialising SkiServlet");
    }

    @POST
    @Path("/{keyname}")
    @Produces(MediaType.APPLICATION_JSON)
    public String createKey(@PathParam("keyname") String keyName,
                            @FormParam("keyvalue") String keyValue,
                         @Context final HttpServletResponse response,
                         @Context final HttpServletRequest request) throws IOException {
        String result = null;

        String token = null;
        Enumeration<String> tkns = request.getHeaders(TOKEN_HEAD);
        if (tkns.hasMoreElements()) {
            token = tkns.nextElement();
        }
        if (token!=null) {
            SkiController sc = new SkiController();
            try {
                String key = sc.createKey(keyName, keyValue, token);
                if (key==null) response.sendError(403);
                else {
                    JSONObject jo = new JSONObject();
                    jo.put("key", key);
                    result = jo.toString();
                }
            } catch (InternalSkiException e) {
                log.log(Level.WARNING, "InternalSkiException on creating key: " + e.getMessage(), e);
                response.sendError(500);
            } catch (JSONException e) {
                log.log(Level.WARNING, "JSONException on creating key: " + e.getMessage(), e);
                response.sendError(500);
            }
        } else {
            response.sendError(401);
        }

        return result;
    }

    @GET
    @Path("/{keyname}")
    @Produces(MediaType.APPLICATION_JSON)
    public String getKey(@PathParam("keyname") String keyName,
                         @Context final HttpServletResponse response,
                         @Context final HttpServletRequest request) throws IOException {
        String result = null;
        String token = null;

        Enumeration<String> tkns = request.getHeaders(TOKEN_HEAD);
        if (tkns.hasMoreElements()) {
            token = tkns.nextElement();
        }

        if (token!=null) {
            SkiController sc = new SkiController();
            try {
                String key = sc.retrieveKey(keyName, token);
                if (key==null) response.sendError(403);
                else {
                    JSONObject jo = new JSONObject();
                    jo.put("key", key);
                    result = jo.toString();
                }
            } catch (InternalSkiException e) {
                log.log(Level.WARNING, "InternalSkiException on fetching key: " + e.getMessage(), e);
                response.sendError(500);
            } catch (JSONException e) {
                log.log(Level.WARNING, "JSONException on fetching key: " + e.getMessage(), e);
                response.sendError(500);
            }
        } else {
            response.sendError(401);
        }

        return result;
    }
}
