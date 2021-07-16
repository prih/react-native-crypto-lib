package com.reactnativecryptolib;

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
        promise.resolve(randomNumber());
    }

    public static native int randomNumber();
}
