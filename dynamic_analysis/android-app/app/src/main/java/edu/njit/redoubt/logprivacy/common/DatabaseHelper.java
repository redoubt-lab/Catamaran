package edu.njit.redoubt.logprivacy.common;

import android.annotation.SuppressLint;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

import edu.njit.redoubt.logprivacy.modle.Config;

public class DatabaseHelper extends SQLiteOpenHelper {

    private static final int DATABASE_VERSION = 1;
    private static final String DATABASE_NAME = "App.db";
    private static DatabaseHelper instance;


    private DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }


    public static synchronized DatabaseHelper getInstance(Context context) {
        if (instance == null) {
            instance = new DatabaseHelper(context.getApplicationContext());
        }
        return instance;
    }


    @Override
    public void onCreate(SQLiteDatabase db) {
        String CREATE_TABLE_CONFIG = "CREATE TABLE IF NOT EXISTS CONFIG (ID INTEGER PRIMARY KEY AUTOINCREMENT, CONFIG_KEY TEXT, CONFIG_VALUE TEXT NOT NULL);";
        db.execSQL(CREATE_TABLE_CONFIG);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS CONFIG");
        onCreate(db);
    }

    @Override
    public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
    }

    public void insertOrUpdateConfig(String configKey, String configValue) {
        SQLiteDatabase db = this.getWritableDatabase();

        Cursor cursor = db.query("CONFIG", new String[]{"CONFIG_KEY"}, "CONFIG_KEY = ?", new String[]{configKey}, null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            updateConfigByKey(configKey, configValue);
        } else {
            ContentValues values = new ContentValues();
            values.put("CONFIG_KEY", configKey);
            values.put("CONFIG_VALUE", configValue);
            db.insert("CONFIG", null, values);
        }

        if (cursor != null) {
            cursor.close();
        }
        db.close();
    }
    @SuppressLint("Range")
    public String getConfigValueByKey(String configKey) {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT CONFIG_VALUE FROM CONFIG WHERE CONFIG_KEY = ?", new String[]{configKey});
        String value = "";
        if (cursor.moveToFirst()) {
            value = cursor.getString(cursor.getColumnIndex("CONFIG_VALUE"));
        }
        cursor.close();
        db.close();
        return value;
    }


    public void updateConfigByKey(String configKey, String configValue) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("CONFIG_VALUE", configValue);
        db.update("CONFIG", values, "CONFIG_KEY = ?", new String[]{configKey});
        db.close();
    }

    public void deleteConfigByKey(String configKey) {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete("CONFIG", "CONFIG_KEY = ?", new String[]{configKey});
        db.close();
    }

    @SuppressLint("Range")
    public List<Config> getAllConfigs() {
        List<Config> configList = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT * FROM CONFIG", null);

        if (cursor.moveToFirst()) {
            do {
                Config config = new Config();
                config.setId(cursor.getInt(cursor.getColumnIndex("ID")));
                config.setKey(cursor.getString(cursor.getColumnIndex("CONFIG_KEY")));
                config.setValue(cursor.getString(cursor.getColumnIndex("CONFIG_VALUE")));
                configList.add(config);
            } while (cursor.moveToNext());
        }
        cursor.close();
        db.close();
        return configList;
    }

}
