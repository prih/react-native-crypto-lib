package com.reactnativecryptolib;

import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = CryptoLibModule.NAME)
public class CryptoLibModule extends ReactContextBaseJavaModule {
    public static final String NAME = "CryptoLib";

    public CryptoLibModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    static {
      try {
        System.loadLibrary("crypto");
        Log.d("libcrypto", "-------- libcrypto-code: loaded");
      } catch (Exception e) {
        Log.d("libcrypto", "-------- libcrypto-code: loaded");
      }
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }


    @ReactMethod
    public void randomNumber(Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            promise.resolve(randomNumber());
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    @ReactMethod
    public void randomBytes(int length, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            byte[] bytes = randomBytes(length);
            promise.resolve(Base64.encodeToString(bytes, Base64.NO_PADDING | Base64.NO_WRAP));
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    @ReactMethod
    public void hash(final int type, final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
            byte[] hash = hash(type, bytes);
            promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    @ReactMethod
    public void hmac(final int type, final String key, final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            byte[] raw_key = Base64.decode(key, Base64.NO_PADDING);
            byte[] raw_data = Base64.decode(data, Base64.NO_PADDING);
            byte[] hash = hmac(type, raw_key, raw_data);
            promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    public static native int randomNumber();
    public static native byte[] randomBytes(int length);
    public static native byte[] hash(int type, byte[] data);
    public static native byte[] hmac(int type, byte[] key, byte[] data);
}
