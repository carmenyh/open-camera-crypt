package net.sourceforge.opencamera.Crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.spongycastle.crypto.AsymmetricBlockCipher;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.crypto.util.PublicKeyFactory;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemObjectParser;
import org.spongycastle.util.io.pem.PemReader;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static android.R.attr.key;

/**
 * Created by bgardon on 3/02/17.
 */

public class ImageEncryptionStream extends OutputStream{
    private PublicKey publicKey;
    private OutputStream out;
    private CipherOutputStream symOut;

    public ImageEncryptionStream(PublicKey publicKey, OutputStream out) {
        if (publicKey == null || out == null) {
            throw new IllegalArgumentException();
        }
        this.publicKey = publicKey;
        this.out = out;
    }

    public void init() throws IOException, InvalidCipherTextException, InvalidKeyException {
        if (publicKey == null || out == null) {
            throw new IllegalStateException("Already initialized");
        }
        if (symOut == null) {
            throw new IllegalStateException("Already closed");
        }
        // Setup a cipher and ouput stream for encrypting the symmetric key and initialization vector
        Cipher rsaCipher;
        try {
            rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return;
        }
        this.publicKey = null;

        // Generate an initialization vector and symmetric key
        SecureRandom random = new SecureRandom();
        byte[] symKey = new byte[32];
        random.nextBytes(symKey);
        byte[] iv = new byte[32];
        random.nextBytes(iv);

        // Write out the symmetric key, then the initialization vector
        //byte[] symKeyCrypt = asymCipher.processBlock(symKey, 0, symKey.length);
        //byte[] ivCrypt = asymCipher.processBlock(iv, 0, iv.length);
        try {
            byte[] symKeyCrypt = rsaCipher.doFinal(symKey);
            out.write(symKeyCrypt.length);
            out.write(iv.length);
            out.write(symKeyCrypt);
            out.write(iv);
            out.flush();
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return;
        }

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
        if (publicKey != null || out != null) {
            throw new IllegalStateException("Not yet initialized");
        }
        if (symOut == null) {
            throw new IllegalStateException("Already closed");
        }
    }
}
