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
import java.nio.charset.Charset;
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

    public String getPublicKeyFilename() {
        String res = this.preferences.getString(PreferenceKeys.getEncryptionInfoPreferenceKey(), "");
        System.err.println(res);
        return res;
    }


    // boolean keyGened = false;
    public void updatePublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.publicKey = AsymmetricKeyReader.readKey(this.getPublicKeyFilename());
    }

    public String getEncryptedImageFolder() {
            String imageFolderPath = this.preferences.getString("PreferenceKeys.getEncryptedImageFolder()", "");
            if (imageFolderPath == null || imageFolderPath.isEmpty()) {
                imageFolderPath = this.preferences.getString(PreferenceKeys.getSaveLocationPreferenceKey(), "OpenCamera");
            }
            return imageFolderPath;
    }

    public class CipherCreationFailedException extends RuntimeException {
        public CipherCreationFailedException(Throwable t) {
            super(t);
        }
    }

    public ImageEncryptionStream getEncryptionStream(OutputStream out, String defaultFileName) throws IOException, CipherCreationFailedException {
        try {
            this.updatePublicKey();
            ImageEncryptionStream encryptionStream = new ImageEncryptionStream(this.publicKey, out);
            encryptionStream.init();

            byte[] filenameBuf = defaultFileName.getBytes("UTF-8");

            // Write out (encrypted) the length of the filename in bytes (little endian)
            encryptionStream.write(filenameBuf.length);
            encryptionStream.write(filenameBuf.length >> 8);
            encryptionStream.write(filenameBuf.length >> 16);
            encryptionStream.write(filenameBuf.length >> 24);

            // Write out the filename
            encryptionStream.write(filenameBuf);

            return encryptionStream;
        } catch (InvalidCipherTextException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CipherCreationFailedException(e);
        }
    }
}
