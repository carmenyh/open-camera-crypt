package net.sourceforge.opencamera.Crypto;

import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.util.PublicKeyFactory;
import org.spongycastle.util.io.pem.PemObject;

/**
 * Created by bgardon on 4/02/17.
 */

// Parses the encoded form of an asymmetric key to a more useful format
public class RSAPublicKeyParser {
    public static AsymmetricKeyParameter parse(byte [] keyEncoding) {
        // TODO implement this
        //PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(this.asymKey)));
        //PemObject pem = pemReader.readPemObject();

        //PublicKeyFactory keyFactory = new PublicKeyFactory();
        //AsymmetricKeyParameter publicKey = keyFactory.createKey(asymKey);
        return null;
    }
}
