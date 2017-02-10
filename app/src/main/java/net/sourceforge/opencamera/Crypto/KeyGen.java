package net.sourceforge.opencamera.Crypto;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

public class KeyGen {

	public static void main(String[] args) {
		DefaultParser parser = new DefaultParser();
		Options options = new Options();
		options.addOption("p", "public", true, "The location at which the generated public key should be stored");
		options.addOption("s", "secret", true, "The location at which the generated private key should be stored");
		options.addOption("d", "device", true, "The location at which a copy of the public key should be stored for the target device");
		CommandLine commandLine;
		try {
			commandLine = parser.parse(options, args);
		} catch (ParseException e) {
			e.printStackTrace();
			return;
		}

		String publicKeyFilename = commandLine.getOptionValue('p', "pub.pem");
		String privateKeyFilename = commandLine.getOptionValue('s', "pub.pem");
		String devicePublicKeyFilename = commandLine.getOptionValue('d');

		KeyPair keys = generateKeys();
		saveKeysToComputer(keys.getPublic(), publicKeyFilename, keys.getPrivate(), privateKeyFilename);
		saveKeyForDevice(keys.getPublic(), devicePublicKeyFilename);
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
	
	public static KeyPair generateKeys() {
		try {
			KeyPairGenerator kg;
			kg = KeyPairGenerator.getInstance("RSA/ECB/NoPadding");
			kg.initialize(1024);
			return kg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	// TODO: Implement Later, encryption of private key to be stored
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

	public static void saveKeysToComputer(PublicKey publickey, String publicFile, PrivateKey privatekey, String privateFile) {
		try {
			PemWriter pempublic = new PemWriter(new FileWriter(new File(publicFile)));
			pempublic.writeObject(new PemObject("RSA PUBLIC KEY", publickey.getEncoded()));
			pempublic.flush();
			pempublic.close();

			PemWriter pemprivate = new PemWriter(new FileWriter(new File(privateFile)));			
			pemprivate.writeObject(new PemObject("RSA PRIVATE KEY", privatekey.getEncoded()));
			pemprivate.flush();
			pemprivate.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void saveKeyForDevice(PublicKey publickey, String SDFile) {
		try {
			PemWriter pempublic = new PemWriter(new FileWriter(new File(SDFile)));
			pempublic.writeObject(new PemObject("RSA PUBLIC KEY", publickey.getEncoded()));
			pempublic.flush();
			pempublic.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
