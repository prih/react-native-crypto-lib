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
          promise.resolve(randomNumber());
        }
      });
    }

    @ReactMethod
    public void randomBytes(int length, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = randomBytes(length);
          promise.resolve(Base64.encodeToString(bytes, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    public static native int randomNumber();
    public static native byte[] randomBytes(int length);
}
