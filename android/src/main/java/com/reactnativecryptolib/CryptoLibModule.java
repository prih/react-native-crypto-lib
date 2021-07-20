package com.reactnativecryptolib;

import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

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


    @ReactMethod(isBlockingSynchronousMethod = true)
    public int randomNumber() {
      return randomNumberNative();
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String randomBytes(int length) {
      byte[] bytes = randomBytesNative(length);
      return Base64.encodeToString(bytes, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String hash(final int type, final String data) {
      byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
      byte[] hash = hashNative(type, bytes);
      return Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String hmac(final int type, final String key, final String data) {
      byte[] raw_key = Base64.decode(key, Base64.NO_PADDING);
      byte[] raw_data = Base64.decode(data, Base64.NO_PADDING);
      byte[] hash = hmacNative(type, raw_key, raw_data);
      return Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    public static native int randomNumberNative();
    public static native byte[] randomBytesNative(int length);
    public static native byte[] hashNative(int type, byte[] data);
    public static native byte[] hmacNative(int type, byte[] key, byte[] data);
}
