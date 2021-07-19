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

    @ReactMethod
    public void sha1(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = sha1(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void sha256(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = sha256(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void sha512(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = sha512(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void sha3_256(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = sha3_256(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void sha3_512(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = sha3_512(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void keccak_256(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = keccak_256(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void keccak_512(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = keccak_512(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    @ReactMethod
    public void ripemd160(final String data, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          byte[] bytes = Base64.decode(data, Base64.NO_PADDING);
          byte[] hash = ripemd160(bytes);
          promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
        }
      });
    }

    public static native int randomNumber();
    public static native byte[] randomBytes(int length);
    public static native byte[] sha1(byte[] data);
    public static native byte[] sha256(byte[] data);
    public static native byte[] sha512(byte[] data);
    public static native byte[] sha3_256(byte[] data);
    public static native byte[] sha3_512(byte[] data);
    public static native byte[] keccak_256(byte[] data);
    public static native byte[] keccak_512(byte[] data);
    public static native byte[] ripemd160(byte[] data);
}
