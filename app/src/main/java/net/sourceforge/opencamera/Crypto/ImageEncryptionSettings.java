package net.sourceforge.opencamera.Crypto;

/**
 * Created by bgardon on 4/02/17.
 */

public class ImageEncryptionSettings {
    private boolean encryptImages;
    private boolean recordExif;
    private boolean encryptExif;
    private String publicKeyFile;
    private byte[] publicKeyEncoding;
    private String encryptedPhotoSaveLocation;

    public boolean isEncryptImages() {
        return encryptImages;
    }

    public void setEncryptImages(boolean encryptImages) {
        this.encryptImages = encryptImages;
    }

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

    public void setPublicKeyFile(String publicKeyFile) {
        this.publicKeyFile = publicKeyFile;
    }

    public byte[] getPublicKeyEncoding() {
        return publicKeyEncoding;
    }

    public void setPublicKeyEncoding(byte[] publicKeyEncoding) {
        this.publicKeyEncoding = publicKeyEncoding;
    }

    public String getEncryptedPhotoSaveLocation() {
        return encryptedPhotoSaveLocation;
    }

    public void setEncryptedPhotoSaveLocation(String encryptedPhotoSaveLocation) {
        this.encryptedPhotoSaveLocation = encryptedPhotoSaveLocation;
    }
}
