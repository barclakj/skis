package com.nfa.skis.client;

import com.nfa.skis.crypt.SkiException;
import com.nfa.skis.servlet.KeyServlet;
import com.nfa.skis.servlet.TokenServlet;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 02/01/2017.
 */
public class SkiClient implements Ski {
    private static Logger log = Logger.getLogger(SkiClient.class.getCanonicalName());

    public static String ROOT_URL = "http://localhost:9080/rest";
    private static final String TOKEN_PATH = "/tokens";
    private static final String GRANT_PATH = "/grant";
    private static final String KEY_PATH = "/keys";

    private static final String ENCODING = "UTF-8";
    private static final String UA = "User-Agent";


    private static final String USER_AGENT = SkiClient.class.getCanonicalName();

    private HttpClient client = HttpClientBuilder.create().build();

    public void revokeIdentity(String identity, String token) throws SkiException {
        try {
            String url = ROOT_URL + TOKEN_PATH + "/" + URLEncoder.encode(identity, ENCODING);
            HttpDelete request = new HttpDelete(url);
            request.addHeader(UA, USER_AGENT);
            request.addHeader(KeyServlet.TOKEN_HEAD, token);

            HttpResponse response = client.execute(request);
            int code = response.getStatusLine().getStatusCode();
            log.info("Response Code : " + code);

            if (code == 200) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

                String line;
                StringBuffer result = new StringBuffer();
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
                boolean success = SkiResponseHandler.confirmAction(TokenServlet.REVOKED_OUTCOME, result.toString());
                log.info("successfully revoked? = " + success);
                if (!success) throw new SkiException("Failed to revoke access to identity: " + identity);
            } else {
                log.warning("Unexpected response code creating key: " + code);
                throw new SkiException("" + code);
            }
        } catch (IOException e) {
            log.log(Level.WARNING, e.getMessage(), e);
        }
    }

    public String grantToken(String identity, String token) throws SkiException {
        String tkn = null;
        try {
            String url = ROOT_URL + TOKEN_PATH + "/" + URLEncoder.encode(identity, ENCODING) + GRANT_PATH;
            HttpPost request = new HttpPost(url);
            request.addHeader(UA, USER_AGENT);
            request.addHeader(KeyServlet.TOKEN_HEAD, token);

            HttpResponse response = client.execute(request);
            int code = response.getStatusLine().getStatusCode();
            log.info("Response Code : " + code);

            if (code == 200) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

                String line;
                StringBuffer result = new StringBuffer();
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
                tkn = SkiResponseHandler.retrieveToken(result.toString());
                log.info("token = " + tkn);
            } else {
                log.warning("Unexpected response code creating key: " + code);
                throw new SkiException("" + code);
            }
        } catch (IOException e) {
            log.log(Level.WARNING, e.getMessage(), e);
        }
        return tkn;
    }

    public String createToken(String identity) throws SkiException {
        String token = null;

        try {
            String url = ROOT_URL + TOKEN_PATH + "/" + URLEncoder.encode(identity, ENCODING);
            HttpPost request = new HttpPost(url);
            request.addHeader(UA, USER_AGENT);

            HttpResponse response = client.execute(request);
            int code = response.getStatusLine().getStatusCode();
            log.info("Response Code : " + code);

            if (code == 200) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

                String line;
                StringBuffer result = new StringBuffer();
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
                token = SkiResponseHandler.retrieveToken(result.toString());
                log.info("token = " + token);
            } else {
                log.warning("Unexpected response code creating token: " + code);
                throw new SkiException("" + code);
            }
        } catch (IOException e) {
            log.log(Level.WARNING, e.getMessage(), e);
        }
        return token;
    }

    public String createKey(String keyName, String keyValue, String token) throws SkiException {
        String key = null;
        try {
            String url = ROOT_URL + KEY_PATH + "/" + URLEncoder.encode(keyName, ENCODING);
            HttpPost request = new HttpPost(url);
            request.addHeader(UA, USER_AGENT);
            request.addHeader(KeyServlet.TOKEN_HEAD, token);

            List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
            urlParameters.add(new BasicNameValuePair("keyvalue", keyValue));

            request.setEntity(new UrlEncodedFormEntity(urlParameters));

            HttpResponse response = client.execute(request);
            int code = response.getStatusLine().getStatusCode();
            log.info("Response Code : " + code);

            if (code == 200) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

                String line;
                StringBuffer result = new StringBuffer();
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
                key = SkiResponseHandler.retrieveKey(result.toString());
                log.info("key = " + key);
            } else {
                log.warning("Unexpected response code creating key: " + code);
                throw new SkiException("" + code);
            }
        } catch (IOException e) {
            log.log(Level.WARNING, e.getMessage(), e);
        }
        return key;
    }

    public String createKey(String keyName, String token) throws SkiException {
        return createKey(keyName, null, token);
    }

    public String getKey(String keyName, String token) throws SkiException {
        String key = null;
        try {
            String url = ROOT_URL + KEY_PATH + "/" + URLEncoder.encode(keyName, ENCODING);
            HttpGet request = new HttpGet(url);
            request.addHeader(UA, USER_AGENT);
            request.addHeader(KeyServlet.TOKEN_HEAD, token);

            HttpResponse response = client.execute(request);
            int code = response.getStatusLine().getStatusCode();
            log.info("Response Code : " + code);

            if (code == 200) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

                String line;
                StringBuffer result = new StringBuffer();
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
                key = SkiResponseHandler.retrieveKey(result.toString());
                log.info("key = " + key);
            } else {
                log.warning("Unexpected response code creating key: " + code);
                throw new SkiException("" + code);
            }
        } catch (IOException e) {
            log.log(Level.WARNING, e.getMessage(), e);
        }
        return key;
    }
}
