package com.masa.vulnerable;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

/** Entry point. Deliberately insecure: this is an analyzer test fixture. */
public class MainActivity extends Activity {

    private static final String TAG = "VulnDemo";

    // Hardcoded credentials of several well-known shapes.
    private static final String AWS_ACCESS_KEY = "AKIA4KJ7XQ2MZLPT9WVC";
    // AWS's own documentation example key: the scanner must NOT report this.
    private static final String AWS_DOC_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String GITHUB_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWxYz";
    private static final String STRIPE_KEY = "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopqrsTU";
    private static final String JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    private static final String ADMIN_PASSWORD = "hunter2-super-secret-admin";
    private static final String HIGH_ENTROPY_BLOB = "Zq7X2pLm9Rt4Wv8Ky3Nc6Bd1Hj5Fg0Sa";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Insecure storage: world-readable preferences.
        SharedPreferences prefs = getSharedPreferences("creds", Context.MODE_WORLD_READABLE);
        prefs.edit().putString("password", ADMIN_PASSWORD).apply();
        prefs.edit().putString("auth_token", JWT).apply();

        SharedPreferences other = getSharedPreferences("shared", Context.MODE_WORLD_WRITEABLE);
        other.edit().putString("aws", AWS_SECRET).apply();

        // Sensitive data written to logs.
        Log.d(TAG, "user password is " + ADMIN_PASSWORD);
        Log.v(TAG, "session token=" + JWT);
        Log.i(TAG, "aws key " + AWS_ACCESS_KEY + " secret " + AWS_SECRET + AWS_DOC_EXAMPLE);

        Log.e(TAG, "github " + GITHUB_TOKEN + " stripe " + STRIPE_KEY + " blob " + HIGH_ENTROPY_BLOB);
    }
}
