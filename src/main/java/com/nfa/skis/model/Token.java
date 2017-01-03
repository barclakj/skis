package com.nfa.skis.model;

/**
 * Created by barclakj on 26/12/2016.
 */
public class Token {
    private String identity = null;
    private byte[] key = null;

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }
}
