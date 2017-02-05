package net.sourceforge.opencamera.Crypto;


import android.app.Activity;
import android.content.Context;

import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/**
 * Created by bgardon on 4/02/17.
 */

public class BogusPublicKeyFileGenerator {
	private Context context;

	public BogusPublicKeyFileGenerator(Context context) {
		this.context = context;
	}

    public void generateBogusPublicKey(String filename) {
        // TODO generate a public/private key pair and then write the public key to the specified file
		KeyPairGenerator kg;
		try {
			kg = KeyPairGenerator.getInstance("RSA");
			kg.initialize(512);
			KeyPair kp = kg.generateKeyPair();
			PublicKey publickey = kp.getPublic();
			PrivateKey privatekey = kp.getPrivate();
			PemWriter pempublic = new PemWriter(new FileWriter(new File(this.context.getFilesDir(), filename)));
			pempublic.writeObject(new PemObject("RSA PUBLIC KEY", publickey.getEncoded()));
			pempublic.flush();
			pempublic.close();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
