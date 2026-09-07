package com.masa.vulnerable;

import java.net.URL;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** TLS validation disabled every way it can be. */
public class NetworkHelper {

    public static final String BASE_URL = "http://api.insecure-demo.example.com/v1/login";
    public static final String TELEMETRY = "http://telemetry.insecure-demo.example.com/collect";

    /** Accepts any certificate chain from anyone. */
    public static class TrustEverything implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public void disableTls() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {new TrustEverything()}, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());

        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

    public void fetch() throws Exception {
        new URL(BASE_URL).openConnection().connect();
        new URL(TELEMETRY).openConnection().connect();
    }
}
