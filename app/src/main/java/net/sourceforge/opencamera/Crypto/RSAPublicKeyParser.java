package net.sourceforge.opencamera.Crypto;

import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by bgardon on 4/02/17.
 */

// Parses the encoded form of an asymmetric key to a more useful format
public class RSAPublicKeyParser {
    public static PublicKey parse(byte [] keyEncoding) {
        // TODO implement this
        //PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(this.asymKey)));
        //PemObject pem = pemReader.readPemObject();

        //PublicKeyFactory keyFactory = new PublicKeyFactory();
        //AsymmetricKeyParameter publicKey = keyFactory.createKey(asymKey);
	try {
	    return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyEncoding));
	} catch (Exception e) {
	    e.printStackTrace();
	}
	return null;
    }
}
