package net.sourceforge.opencamera.Crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import net.sourceforge.opencamera.PreferenceKeys;

import org.spongycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by bgardon on 4/02/17.
 */

public class Encryptor {
    private Context context;
    private SharedPreferences preferences;
    private PublicKey publicKey;

    public Encryptor(Context context) {
        this.context = context;
        this.preferences = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public boolean isEncryptionOn() {
        return this.preferences.getBoolean(PreferenceKeys.getEncryptPreferenceKey(), false);
    }

//    public boolean isRecordExifOn() {
//        return this.preferences.getBoolean(PreferenceKeys.getRecordExifKeyKey(), false);
//    }

    public String getPublicKeyFilename() {
        return this.preferences.getString(PreferenceKeys.getEncryptionKeyKey(), "");
    }

    public void updatePublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.publicKey = AsymmetricKeyReader.readKey(this.getPublicKeyFilename());
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

//    public String getEncryptedPhotoSaveLocation() {
//        return this.preferences.getString(PreferenceKeys.getEncryptionSaveLocationKey(), this.preferences.getString(PreferenceKeys.getSaveLocationKey(), ""));
//    }

    public ImageEncryptionStream getEncryptionStream(OutputStream out) throws InvalidKeyException, IOException, InvalidCipherTextException {
        try {
            this.updatePublicKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        ImageEncryptionStream encryptionStream = new ImageEncryptionStream(this.publicKey, out);
        encryptionStream.init();
        return encryptionStream;
    }
}
