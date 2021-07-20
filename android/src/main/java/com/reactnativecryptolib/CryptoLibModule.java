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

    @ReactMethod(isBlockingSynchronousMethod = true)
    public int randomNumber() {
      return randomNumberNative();
    }

    @ReactMethod
    public void randomBytes(int length, Promise promise) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            byte[] bytes = randomBytesNative(length);

            promise.resolve(Base64.encodeToString(bytes, Base64.NO_PADDING | Base64.NO_WRAP));
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String randomBytesSync(int length) {
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

    @ReactMethod
    public void pbkdf2(
      final int type,
      final String pass,
      final String salt,
      final int iterations,
      final int keyLength,
      Promise promise
    ) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            byte[] raw_pass = Base64.decode(pass, Base64.NO_PADDING);
            byte[] raw_salt = Base64.decode(salt, Base64.NO_PADDING);
            byte[] hash = pbkdf2Native(type, raw_pass, raw_salt, iterations, keyLength);

            promise.resolve(Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP));
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String pbkdf2Sync(
      final int type,
      final String pass,
      final String salt,
      final int iterations,
      final int keyLength
    ) {
      byte[] raw_pass = Base64.decode(pass, Base64.NO_PADDING);
      byte[] raw_salt = Base64.decode(salt, Base64.NO_PADDING);
      byte[] hash = pbkdf2Native(type, raw_pass, raw_salt, iterations, keyLength);

      return Base64.encodeToString(hash, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    @ReactMethod
    public void mnemonicToSeed(
      final String mnemonic,
      final String passphrase,
      Promise promise
    ) {
      AsyncTask.execute(new Runnable() {
        @Override
        public void run() {
          try {
            byte[] seed = mnemonicToSeedNative(mnemonic, passphrase);
            promise.resolve(Base64.encodeToString(seed, Base64.NO_PADDING | Base64.NO_WRAP));
          } catch (Exception ex) {
            ex.printStackTrace();
            promise.reject("Error", ex.toString());
          }
        }
      });
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String mnemonicToSeedSync(
      final String mnemonic,
      final String passphrase
    ) {
      byte[] seed = mnemonicToSeedNative(mnemonic, passphrase);
      return Base64.encodeToString(seed, Base64.NO_PADDING | Base64.NO_WRAP);
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String generateMnemonic(
      final int strength
    ) {
      return generateMnemonicNative(strength);
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public int validateMnemonic(
      final String mnemonic
    ) {
      return validateMnemonicNative(mnemonic);
    }

    public static native int randomNumberNative();
    public static native byte[] randomBytesNative(int length);
    public static native byte[] hashNative(int type, byte[] data);
    public static native byte[] hmacNative(int type, byte[] key, byte[] data);
    public static native byte[] pbkdf2Native(int type, byte[] pass, byte[] salt, int iterations, int keyLength);
    public static native byte[] mnemonicToSeedNative(String mnemonic, String passphrase);
    public static native String generateMnemonicNative(int strength);
    public static native int validateMnemonicNative(String mnemonic);
}
