package net.sourceforge.opencamera.Crypto;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Environment;
import android.util.Log;

import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.util.PrivateKeyFactory;
import org.spongycastle.crypto.util.PrivateKeyInfoFactory;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;

import static android.content.ContentValues.TAG;

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
 * Created by bgardon on 3/02/17.
 */

public class ReadAsymmetricKey /* extends Activity */ {
    public static byte[] readKey(String filename) throws IOException {
	/*
        File f = new File(filename);
        int fileSize = (int)f.length();
        FileInputStream in = new FileInputStream(f);
        byte[] res = new byte[fileSize];
        int totalRead = 0;
        while (totalRead < fileSize) {
            in.read(res, totalRead, fileSize - totalRead);
        }
        return res;
	*/
	try {
	    PemReader pempublic = new PemReader(new FileReader(new File("public.pem")));
	    byte[] bytes = pempublic.readPemObject().getContent();
	    return bytes;
	} catch (FileNotFoundException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (IOException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (InvalidKeySpecException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
	return null;
    }
}
