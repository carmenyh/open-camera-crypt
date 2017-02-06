import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.Cipher;

import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

public class KeyGen {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		//String password = getPassword();
		KeyPair keys = generateKeys();
		//byte[] encrypted = encryptPrivate(keys.getPrivate(), password);
		writeKeysToComputer(keys.getPublic(), keys.getPrivate());
		writeKeyToSD(keys.getPublic());

	}

	/*
	private static String getPassword() {
		Scanner input = new Scanner(System.in);
		System.out.print("Input a password to protect the private key: ");
		String passcode = input.next();
		input.close();
		return passcode;
	}
	*/
	
	private static KeyPair generateKeys() {
		try {
			KeyPairGenerator kg;
			kg = KeyPairGenerator.getInstance("RSA");
			kg.initialize(512);
			return kg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	/*
	 * Implement Later, encryption of private key to be stored
	 */
	/*
	private static byte[] encryptPrivate(PrivateKey privatekey, String password) {
		// Hash password
		
		try {
			MessageDigest md;
			md = MessageDigest.getInstance("MD5");
			md.update(password.getBytes());
	        //Get the hash's bytes 
	        byte[] keyKey = md.digest();
	        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
	        cipher.in
	        
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        //Add password bytes to digest
        
		// Encrypt with AES
		return null;
	}
	*/
	private static void writeKeysToComputer(PublicKey publickey, PrivateKey privatekey) {
		try {
			PemWriter pempublic = new PemWriter(new FileWriter(new File("public.pem")));
			pempublic.writeObject(new PemObject("RSA PUBLIC KEY", publickey.getEncoded()));
			pempublic.flush();
			pempublic.close();
			PemWriter pemprivate = new PemWriter(new FileWriter(new File("private.pem")));			
			pemprivate.writeObject(new PemObject("RSA PRIVATE KEY", privatekey.getEncoded()));
			pemprivate.flush();
			pemprivate.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	private static void writeKeyToSD(PublicKey publickey) {
		// TODO Auto-generated method stub
		
	}
	
}
