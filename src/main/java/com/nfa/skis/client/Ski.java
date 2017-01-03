package com.nfa.skis.client;

import com.nfa.skis.crypt.SkiException;

/**
 * Created by barclakj on 02/01/2017.
 */
public interface Ski {
    void revokeIdentity(String identity, String token) throws SkiException;
    String grantToken(String identity, String token) throws SkiException;
    String createToken(String identity) throws SkiException;
    String createKey(String keyName, String keyValue, String token) throws SkiException;
    String createKey(String keyName, String token) throws SkiException;
    String getKey(String keyName, String token) throws SkiException;
}
