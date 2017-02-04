package net.sourceforge.opencamera.Crypto;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by bgardon on 4/02/17.
 */

public class Encryptor {
    private boolean encryptionOn;
    private boolean recordExif;
    private boolean encryptExif;
    private String publicKeyFile;
    private PublicKey publicKey;
    private String encryptedPhotoSaveLocation;

    public boolean isEncryptionOn() {
        return encryptionOn;
    }

    public void setEncryptionOn(boolean encryptOn) { this.encryptionOn = encryptOn; }

    public boolean isRecordExif() {
        return recordExif;
    }

    public void setRecordExif(boolean recordExif) {
        this.recordExif = recordExif;
    }

    public boolean isEncryptExif() {
        return encryptExif;
    }

    public void setEncryptExif(boolean encryptExif) {
        this.encryptExif = encryptExif;
    }

    public String getPublicKeyFile() {
        return publicKeyFile;
    }

    public void setPublicKeyFile(String publicKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.publicKeyFile = publicKeyFile;
        this.publicKey = AsymmetricKeyReader.readKey(publicKeyFile);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getEncryptedPhotoSaveLocation() {
        return encryptedPhotoSaveLocation;
    }

    public void setEncryptedPhotoSaveLocation(String encryptedPhotoSaveLocation) {
        this.encryptedPhotoSaveLocation = encryptedPhotoSaveLocation;
    }

    public ImageEncryptionStream getEncryptionStream(OutputStream out) {
        return new ImageEncryptionStream(this.publicKey, out);
    }
}
