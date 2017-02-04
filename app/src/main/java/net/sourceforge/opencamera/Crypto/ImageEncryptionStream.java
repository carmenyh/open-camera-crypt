package net.sourceforge.opencamera.Crypto;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.SecureRandom;

import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.util.PublicKeyFactory;

/**
 * Created by bgardon on 3/02/17.
 */

public class ImageEncryptionStream extends OutputStream{
    private byte[] asymKey;
    private OutputStream out;
    private CipherOutputStream symOut;

    public ImageEncryptionStream(byte[] asymKey, OutputStream out) {
        if (asymKey == null || out == null) {
            throw new IllegalArgumentException();
        }
        this.asymKey = asymKey;
        this.out = out;
    }

    public void init() throws IOException {
        if (asymKey == null || out == null) {
            throw new IllegalStateException("Already initialized");
        }
        if (symOut == null) {
            throw new IllegalStateException("Already closed");
        }
        // Setup a cipher and ouput stream for encrypting the symmetric key and initialization vector
        PublicKeyFactory keyFactory = new PublicKeyFactory();
        AsymmetricKeyParameter publicKey = keyFactory.createKey(asymKey);
        StreamCipher asymCipher = new Salsa20Engine();
        asymCipher.init(true, publicKey);
        CipherOutputStream asymOut  = new CipherOutputStream(out, asymCipher);

        this.asymKey = null;

        // Generate an initialization vector and symmetric key
        SecureRandom random = new SecureRandom();
        byte[] symKey = new byte[32];
        random.nextBytes(symKey);
        byte[] iv = new byte[32];
        random.nextBytes(iv);

        // Write out the symmetric key, then the initialization vector
        asymOut.write(symKey);
        asymOut.write(iv);
        asymOut.flush();
        asymOut.close();

        // Set up a cipher and ouput stream for encoding the image data
        StreamCipher cipher = new Salsa20Engine();
        cipher.init(true, new ParametersWithIV(new KeyParameter(symKey), iv));
        this.symOut = new CipherOutputStream(out, cipher);

        this.out = null;
    }

    @Override
    public void close() throws IOException  {
        checkState();
        this.symOut.close();
        this.symOut = null;
    }

    @Override
    public void flush() throws IOException {
        checkState();
        this.symOut.flush();
    }

    @Override
    public void write(byte[] b) throws IOException {
        checkState();
        this.symOut.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        checkState();
        this.symOut.write(b, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        checkState();
        this.symOut.write(b);
    }

    private void checkState() {
        if (asymKey != null || out != null) {
            throw new IllegalStateException("Not yet initialized");
        }
        if (symOut == null) {
            throw new IllegalStateException("Already closed");
        }
    }
}
