package net.sourceforge.opencamera.Crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import net.sourceforge.opencamera.MainActivity;
import net.sourceforge.opencamera.PreferenceKeys;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by bgardon on 4/02/17.
 */

public class Encryptor {
    static public String FILE_EXTENSION = "encrypted";

    private MainActivity mainActivity;
    private SharedPreferences preferences;
    private PublicKey publicKey;

    public Encryptor(MainActivity mainActivity) {
        this.mainActivity = mainActivity;
        this.preferences = PreferenceManager.getDefaultSharedPreferences(mainActivity);
    }

    public boolean isEncryptionOn() {
        return this.preferences.getBoolean(PreferenceKeys.getEncryptPreferenceKey(), false);
    }

//    public boolean isRecordExifOn() {
//        return this.preferences.getBoolean(PreferenceKeys.getRecordExifKeyKey(), false);
//    }

    public String getPublicKeyFilename() {
        return this.preferences.getString(PreferenceKeys.getEncryptionInfoPreferenceKey(), "");
    }


    boolean keyGened = false;
    public void updatePublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        if (!keyGened) {
            KeyPair keys = KeyGen.generateKeys();
            KeyGen.writeKeysToComputer(keys.getPublic(), this.getPublicKeyFilename() + "/pub.pem",
                    keys.getPrivate(), this.getPublicKeyFilename() + "/priv.pem");
            keyGened = true;
        }

        this.publicKey = AsymmetricKeyReader.readKey(this.getPublicKeyFilename() + "/pub.pem");
    }

    public String getEncryptedImageFolder() {
            String imageFolderPath = this.preferences.getString("sjdnfjhjkdhdjkn"/*PreferenceKeys.getEncryptedImageFolder()*/, "");
            if (imageFolderPath == null || imageFolderPath.equals("")) {
                imageFolderPath = this.preferences.getString(PreferenceKeys.getSaveLocationPreferenceKey(), "OpenCamera");
            }
            return imageFolderPath;
    }

    public class CipherCreationFailedException extends RuntimeException {
        public CipherCreationFailedException(Throwable t) {
            super(t);
        }
    }

    public ImageEncryptionStream getEncryptionStream(OutputStream out) throws IOException, CipherCreationFailedException {
        try {
            this.updatePublicKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        ImageEncryptionStream encryptionStream = new ImageEncryptionStream(this.publicKey, out);
        try {
            encryptionStream.init();
        } catch (InvalidCipherTextException e) {
            throw new CipherCreationFailedException(e);
        } catch (InvalidKeyException e) {
            throw new CipherCreationFailedException(e);
        }
        return encryptionStream;
    }
}
