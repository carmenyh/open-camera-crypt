package net.sourceforge.opencamera.Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.io.CipherInputStream;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.io.pem.PemReader;

public class Decryptor {
	public static void main(String[] args) {
		PrivateKey privatekey = getPrivateKey();
		File fi = new File(args[0]);
		File fo = new File(args[1]);
		godMethod(privatekey, fi, fo);
	}
	
	public static byte[] godMethod(PrivateKey privatekey, File fi, File fo) {
		try {
			long length = fi.length();
			FileInputStream fr = new FileInputStream(fi);
			int sklength = fr.read();
			int ivlength = fr.read();
			
			length = length - (sklength + ivlength + 1 + 1);
			byte[] key = getSymmetricKey(fr, sklength);
			key = decryptSymmetricKey(privatekey, key);
			byte[] iv = getIV(fr, ivlength);
			byte[] photo =  getEncryptedPhoto(fr, length);
			FileOutputStream fos = new FileOutputStream(fo);
			storeDecryptPhoto(key, iv, fos, photo);
			
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static void storeDecryptPhoto(byte[] symKey, byte[] iv, FileOutputStream out, byte[] encryptedphoto) throws IOException {
        StreamCipher cipher = new Salsa20Engine();
        cipher.init(false, new ParametersWithIV(new KeyParameter(symKey), iv));
        CipherOutputStream symOut = new CipherOutputStream(out, cipher);
        symOut.write(encryptedphoto);;
        symOut.close(); 
	}

	private static byte[] decryptPhoto(FileInputStream f, byte[] key, byte[] iv, long length) {
		
        try {
        	byte[] photo = new byte[(int) length];
            StreamCipher cipher = new Salsa20Engine();
            cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
            CipherInputStream input = new CipherInputStream(f, cipher);
			input.read(photo);
			input.close();
			return photo;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
		
	}
	
	public static byte[] getEncryptedPhoto(FileInputStream f, long length) {
		System.out.println(length);
		
        try {
        	byte[] photo = new byte[(int) length];
			f.read(photo);
			return photo;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
		
	}

	private static byte[] getIV(FileInputStream f, int ivlength) {
		
		try {
			byte[] buf = new byte[ivlength];
			f.read(buf);
			return buf;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	private static byte[] decryptSymmetricKey(PrivateKey privatekey, byte[] key) {
		
        try {
        	Cipher rsaCipher = Cipher.getInstance("RSA");
			rsaCipher.init(Cipher.DECRYPT_MODE, privatekey);
			byte[] keyE = rsaCipher.doFinal(key);
			return keyE;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
        
		// TODO Auto-generated method stub
		
	}

	private static byte[] getSymmetricKey(FileInputStream f, int length) {
		// TODO Auto-generated method stub
		try {
			byte[] buf = new byte[length];
			f.read(buf);
			return buf;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	}

	public static PrivateKey getPrivateKey() {
		try {
			PemReader pempublic = new PemReader(new FileReader(new File("private.pem")));
			byte[] bytes = pempublic.readPemObject().getContent();
			PrivateKey pub = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
			pempublic.close();
			return pub;
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
