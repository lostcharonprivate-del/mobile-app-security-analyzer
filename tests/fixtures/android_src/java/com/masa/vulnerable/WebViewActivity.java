package com.masa.vulnerable;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.webkit.WebSettings;

/** WebView with every guard turned off. */
@SuppressLint("SetJavaScriptEnabled")
public class WebViewActivity extends Activity {

    public class Bridge {
        @JavascriptInterface
        public String getSecret() {
            return "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopqrsTU";
        }
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setDomStorageEnabled(true);

        webView.addJavascriptInterface(new Bridge(), "AndroidBridge");
        webView.loadUrl(getIntent().getStringExtra("url"));
        setContentView(webView);
    }
}
