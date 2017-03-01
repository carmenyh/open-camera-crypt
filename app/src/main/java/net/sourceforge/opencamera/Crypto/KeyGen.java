package net.sourceforge.opencamera.Crypto;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;



import java.io.ByteArrayOutputStream;
import java.io.CharArrayWriter;
public class KeyGen {

	public static void main(String[] args) {
		DefaultParser parser = new DefaultParser();
		Options options = new Options();
		options.addOption("p", "public", true, "The location at which the generated public key should be stored");
		options.addOption("s", "secret", true, "The location at which the generated private key should be stored");
		options.addOption("d", "device", true, "The location at which a copy of the public key should be stored for the target device");
        options.addOption("k", "key", true, "The password with which to protect the private key");
		CommandLine commandLine;
		try {
			commandLine = parser.parse(options, args);
		} catch (ParseException e) {
			e.printStackTrace();
			return;
		}

		String publicKeyFilename = commandLine.getOptionValue('p', "pub.pem");
		String privateKeyFilename = commandLine.getOptionValue('s', "priv.pem");
		String devicePublicKeyFilename = commandLine.getOptionValue('d', "pub.pem");
        String privateKeyPasscode = commandLine.getOptionValue('k', "");

		KeyPair keys = generateKeys();
		saveKeysToComputer(keys.getPublic(), publicKeyFilename, keys.getPrivate(), privateKeyFilename, privateKeyPasscode);
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
			kg = KeyPairGenerator.getInstance("RSA");
			kg.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));
			return kg.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
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

	public static void saveKeysToComputer(PublicKey publickey, String publicFile, PrivateKey privatekey, String privateFile, String passcode) {
		try {
			writeEncryptedPrivate(privatekey, privateFile, passcode);
			
			PemWriter pempublic = new PemWriter(new FileWriter(new File(publicFile)));
			pempublic.writeObject(new PemObject("RSA PUBLIC KEY", publickey.getEncoded()));
			pempublic.flush();
			pempublic.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

    private static void writeEncryptedPrivate(PrivateKey privateKey, String privateFile, String privateKeyPassCode) {
        try {
            CharArrayWriter output = new CharArrayWriter();
            PemWriter pempublic = new PemWriter(output);
            pempublic.writeObject(new PemObject("RSA PRIVATE KEY", privateKey.getEncoded()));
            pempublic.flush();
            pempublic.close();
            FileOutputStream file = new FileOutputStream(new File(privateFile));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(privateKeyPassCode.getBytes("UTF-8"));
            byte[] passcode = md.digest();
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[8];
            random.nextBytes(iv);
            file.write(iv.length);
            file.write(iv);
            StreamCipher cipher = new Salsa20Engine();
            cipher.init(true, new ParametersWithIV(new KeyParameter(passcode), iv));
            CipherOutputStream keyStream = new CipherOutputStream(file, cipher);
            keyStream.write((new String(output.toCharArray())).getBytes());
            keyStream.flush();
            keyStream.close();



            /*
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            */
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
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
