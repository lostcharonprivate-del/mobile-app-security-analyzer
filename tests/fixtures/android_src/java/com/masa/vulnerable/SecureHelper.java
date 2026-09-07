package com.masa.vulnerable;

import android.content.Context;
import android.content.SharedPreferences;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Correct usage, kept alongside the broken code as a false-positive control:
 * nothing in this class should produce a finding.
 */
public class SecureHelper {

    public byte[] encrypt(byte[] plaintext) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey key = generator.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plaintext);
    }

    public byte[] digest(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    public void store(Context context, String value) {
        SharedPreferences prefs = context.getSharedPreferences("safe", Context.MODE_PRIVATE);
        prefs.edit().putString("display_name", value).apply();
    }

    public String endpoint() {
        return "https://api.example.com/v1/secure";
    }
}
