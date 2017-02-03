package net.sourceforge.opencamera.Crypto;

import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.io.CipherOutputStream;

/**
 * Created by bgardon on 3/02/17.
 */

public class ImageEncryptionStream extends OutputStream{
    private CipherOutputStream out;

    public ImageEncryptionStream(int asymKey, int symKey, OutputStream out) {
        StreamCipher cipher = new Salsa20Engine();
        cipher.init(true, new Something);
        this.out = new CipherOutputStream(out, cipher);
    }

    @Override
    public void close() throws IOException {
        this.out.close();
    }

    @Override
    public void flush() throws IOException{
        this.out.flush();
    }

    @Override
    public void write(byte[] b) throws IOException {
        this.out.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        this.out.write(b, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        this.out.write(b);
    }
}
