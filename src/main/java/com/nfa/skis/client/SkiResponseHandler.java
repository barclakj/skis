package com.nfa.skis.client;

import com.nfa.skis.servlet.TokenServlet;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 02/01/2017.
 */
public class SkiResponseHandler {
    private static Logger log = Logger.getLogger(SkiResponseHandler.class.getCanonicalName());

    private static final String TOKEN_FIELD = "token";
    private static final String KEY_FIELD = "key";
    private static final String ACTION_FIELD = "action";

    public static boolean confirmAction(String expectedAction, String jsonData) {
        boolean rval = false;
        try {
            JSONObject jo = new JSONObject(jsonData);
            if (jo.has(ACTION_FIELD)) {
                String act = jo.getString(ACTION_FIELD);
                if (expectedAction.equalsIgnoreCase(act)) {
                    rval = true;
                }
            }
        } catch (JSONException e) {
            log.log(Level.WARNING, "Cannot parse string to validate action: " + jsonData + " Msg: " + e.getMessage(), e);
        }
        return rval;
    }

    public static String retrieveToken(String jsonData) {
        String tkn = null;
        try {
            JSONObject jo = new JSONObject(jsonData);
            if (jo.has(TOKEN_FIELD)) {
                tkn = jo.getString(TOKEN_FIELD);
            }
        } catch (JSONException e) {
            log.log(Level.WARNING, "Cannot parse token string: " + jsonData + " Msg: " + e.getMessage(), e);
        }
        return tkn;
    }

    public static String retrieveKey(String jsonData) {
        String k = null;
        try {
            JSONObject jo = new JSONObject(jsonData);
            if (jo.has(KEY_FIELD)) {
                k = jo.getString(KEY_FIELD);
            }
        } catch (JSONException e) {
            log.log(Level.WARNING, "Cannot parse key string: " + jsonData + " Msg: " + e.getMessage(), e);
        }
        return k;
    }
}
