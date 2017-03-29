package com.nfa.skis.crypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by barclakj on 26/12/2016.
 */
@Component
public class BasicJCECrypter implements ICrypter {
    public static Logger log = Logger.getLogger(BasicJCECrypter.class.getCanonicalName());

    private static int AES_KEYLENGTH = 128;
    private static int ivLengthBytes = AES_KEYLENGTH / 8;	// Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later

    static {
        Security.addProvider(new BouncyCastleProvider());
    }



    public byte[] encrypt(byte[] data, byte[] key) throws SkiException {
        byte[] byteCipherText = null;
        Key k = SkiKeyGen.keyFromBytes(key);

        byte[] iv = Arrays.copyOfRange(key, 0, ivLengthBytes);

        try {
            Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));

            byteCipherText = aesCipherForEncryption.doFinal(data);
        } catch (NoSuchProviderException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (BadPaddingException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (IllegalBlockSizeException e ){
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (InvalidAlgorithmParameterException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (InvalidKeyException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (NoSuchPaddingException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (NoSuchAlgorithmException e ) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } finally {

        }
        return byteCipherText;
    }

    public  byte[] decrypt(byte[] data, byte[] key) throws SkiException {
        byte[] rawText = null;
        Key k = SkiKeyGen.keyFromBytes(key);

        byte[] iv = Arrays.copyOfRange(key, 0, ivLengthBytes);

        try {
            Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
            rawText = aesCipherForDecryption.doFinal(data);
        } catch (NoSuchProviderException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (BadPaddingException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (IllegalBlockSizeException e ){
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (InvalidAlgorithmParameterException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (InvalidKeyException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (NoSuchPaddingException e) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } catch (NoSuchAlgorithmException e ) {
            log.log(Level.WARNING, e.getClass().getCanonicalName() + " " + e.getMessage(), e);
            throw new SkiException(e);
        } finally {

        }
        return rawText;
    }


}
