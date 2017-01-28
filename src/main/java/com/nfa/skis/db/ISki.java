package com.nfa.skis.db;

import com.nfa.skis.crypt.InternalSkiException;

/**
 * Created by barclakj on 28/01/2017.
 */
public interface ISki {
    public boolean checkBlacklist(String identity) throws InternalSkiException;
    public int blacklistIdentity(String identity) throws InternalSkiException;
    public int saveKeyPair(String keyName, String keyValue) throws InternalSkiException;
    public int updateKeyPair(String keyName, String keyValue) throws InternalSkiException;
    public String fetchKey(String keyName) throws InternalSkiException;
    public int saveSystemKey(String keyName, String keyValue) throws InternalSkiException;
    public String lookupSystemKey(String keyName) throws InternalSkiException;

}
