package com.masa.vulnerable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Broken cryptography in several classic shapes. */
public class CryptoHelper {

    // Hardcoded symmetric key and IV.
    private static final byte[] KEY = "0123456789abcdef".getBytes();
    private static final byte[] IV = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    public byte[] encryptDes(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "DES"));
        return cipher.doFinal(plaintext);
    }

    public byte[] encryptEcb(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return cipher.doFinal(plaintext);
    }

    public byte[] encryptRc4(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "RC4"));
        return cipher.doFinal(plaintext);
    }

    public byte[] encryptStaticIv(byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
        return cipher.doFinal(plaintext);
    }

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(password.getBytes());
        return new String(md5.digest(password.getBytes()));
    }

    public int predictableRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(1234567890L);
        return random.nextInt();
    }
}
