package com.masa.vulnerable;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.Environment;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/** Writes app data to places other apps can read. */
public class StorageHelper {

    public void writeToken(Context context, String token) throws IOException {
        // Unencrypted database in app storage.
        SQLiteDatabase db = context.openOrCreateDatabase("secrets.db", Context.MODE_PRIVATE, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS tokens (value TEXT)");
        db.execSQL("INSERT INTO tokens VALUES ('" + token + "')");

        // World-readable file mode.
        FileOutputStream fos = context.openFileOutput("token.txt", Context.MODE_WORLD_READABLE);
        fos.write(token.getBytes());
        fos.close();

        // Public external storage: readable by any app with storage permission.
        File external = Environment.getExternalStorageDirectory();
        File out = new File(external, "vulnapp/credentials.txt");
        FileOutputStream ext = new FileOutputStream(out);
        ext.write(token.getBytes());
        ext.close();

        File downloads = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
        new FileOutputStream(new File(downloads, "backup.json")).close();
    }
}
