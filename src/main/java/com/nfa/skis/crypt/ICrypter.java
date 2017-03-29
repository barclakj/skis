package com.nfa.skis.crypt;

import org.springframework.stereotype.Component;

/**
 * Created by barclakj on 11/02/2017.
 */
public interface ICrypter {
    public byte[] encrypt(byte[] data, byte[] key) throws SkiException;
    public byte[] decrypt(byte[] data, byte[] key) throws SkiException;
}

