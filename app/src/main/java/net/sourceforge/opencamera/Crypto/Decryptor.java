package net.sourceforge.opencamera.Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.spongycastle.crypto.StreamCipher;
import org.spongycastle.crypto.engines.Salsa20Engine;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.io.pem.PemReader;

import java.io.ByteArrayOutputStream;
import java.io.CharArrayReader;
import java.security.MessageDigest;

public class Decryptor {
	private static boolean DEBUG = true;

	private static void debugPrint(String s) {
		if (DEBUG) {
			System.out.println(s);
		}
	}

	public static void main(String[] args) {
		DefaultParser parser = new DefaultParser();
        Options options = new Options();
        options.addOption("s", "secret", true, "The path of the private key file to be used to decrypt the image");
        options.addOption("d", "use-directory", false, "Decrypt all encrypted photos in a directory");
		options.addOption("k", "key", true, "The password with which to protect the private key");
        CommandLine commandLine;
        try {
            commandLine = parser.parse(options, args);
        } catch (ParseException e) {
            e.printStackTrace();
            return;
        }

		String privateKeyFilepath = commandLine.getOptionValue('s', "");
		if (privateKeyFilepath.isEmpty()) {
			printAndExit("No private key file specified.");
		}
		String privateKeyPasscode = commandLine.getOptionValue('k', "");
		PrivateKey privateKey = getPrivateKey(privateKeyFilepath, privateKeyPasscode);

		String[] paths = commandLine.getArgs();
		if (paths.length != 2) {
			printAndExit("Incorrect number of arguments.");
		}
		File inputPath = new File(paths[0]);
		File outputPath = new File(paths[1]);

		if (!outputPath.isDirectory()) {
			printAndExit("Output path must be a directory.");
		}

		boolean useDir = commandLine.hasOption('d');
		if (useDir) {
			if (!inputPath.isDirectory()) {
				printAndExit("Input path must be a directory.");
			}
			File[] files = inputPath.listFiles(new FilenameFilter() {
				@Override
				public boolean accept(File dir, String name) {
					return name.endsWith(".encrypted");
				}
			});
			for (File encryptedFile : files) {
				decryptSingleFile(privateKey, encryptedFile, outputPath);
			}
		} else {
			if (!inputPath.isFile()) {
				printAndExit("Input path must be a file.");
			}
			decryptSingleFile(privateKey, inputPath, outputPath);
		}
	}

	private static void printAndExit(String message) {
		System.err.println(message);
		System.exit(1);
	}

	private static byte[] decryptSingleFile(PrivateKey privatekey, File fileIn, File dirOut) {
		debugPrint("Decrypting: " + fileIn.getAbsolutePath());

		try {
			long fileLength = fileIn.length();
			debugPrint("\tFile length:\t\t" + fileLength);

			InputStream fr = new FileInputStream(fileIn);

			// Calculate the length of the various parts of the encrypted file
			int sklength = fr.read();
			debugPrint("\tEncrypted symmetric key length:\t" + sklength);
			int ivlength = fr.read();
			debugPrint("\tInitialization vector length:\t" + ivlength);
			//int imageLength = (int)fileLength - (sklength + ivlength + 1 + 1);
			int encryptedLength = (int)fileLength - (sklength + ivlength + 1 + 1);
			debugPrint("\tTotal encrypted length:\t" + encryptedLength);

			// Read the symmetric key
			byte[] encryptedKey = new byte[sklength];
			int encKeyBytesRead = 0;
			while (encKeyBytesRead < sklength) {
				encKeyBytesRead += fr.read(encryptedKey, encKeyBytesRead, sklength - encKeyBytesRead);
			}
			byte[] key = decryptSymmetricKey(privatekey, encryptedKey);

			// Read the initialization vector
			byte[] iv = new byte[ivlength];
			int ivBytesRead = 0;
			while (ivBytesRead < ivlength) {
				ivBytesRead += fr.read(iv, ivBytesRead, ivlength - ivBytesRead);
			}

			// Decrypt and write out the photo
			decryptAndStorePhoto(key, iv, dirOut, fr, encryptedLength);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static void decryptAndStorePhoto(byte[] symKey, byte[] iv, File dirOut, InputStream in, int length) throws IOException {
		debugPrint("\tDecrypting data portion of photo");
        StreamCipher cipher = new Salsa20Engine();
        cipher.init(false, new ParametersWithIV(new KeyParameter(symKey), iv));

		// Read in the output filename length
		byte[] outputFilenameLengthBytes = new byte[4];
		in.read(outputFilenameLengthBytes);
		int outFilenameLength = cipher.returnByte(outputFilenameLengthBytes[0]);
		outFilenameLength += cipher.returnByte(outputFilenameLengthBytes[1]) << 8;
		outFilenameLength += cipher.returnByte(outputFilenameLengthBytes[2]) << 16;
		outFilenameLength += cipher.returnByte(outputFilenameLengthBytes[3]) << 24;
		debugPrint("\tOutput filename length:\t" + outFilenameLength);

		byte[] outputFilenameBytes = new byte[outFilenameLength];
		in.read(outputFilenameBytes);
		for (int i = 0; i < outFilenameLength; i++) {
			outputFilenameBytes[i] = cipher.returnByte(outputFilenameBytes[i]);
		}
		String outputFilename = new String(outputFilenameBytes, "UTF-8");
		File outputFile = new File(dirOut, outputFilename);
		debugPrint("\tOutput filename:\t\t" + outputFile.getAbsolutePath());

		CipherOutputStream symOut = new CipherOutputStream(new FileOutputStream(outputFile), cipher);

		byte[] buffer = new byte[2048];
		long bytesRead = 0;
		while (bytesRead < length - outputFilenameLengthBytes.length - outputFilenameBytes.length) {
			int read = in.read(buffer);
			symOut.write(buffer, 0, read);
			bytesRead += read;
		}

        symOut.close();
		debugPrint("\tDone decrypting photo");
	}

	private static byte[] decryptSymmetricKey(PrivateKey privatekey, byte[] encryptedKey) {
        try {
        	Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
			rsaCipher.init(Cipher.DECRYPT_MODE, privatekey);
			byte[] decryptedBlock = rsaCipher.doFinal(encryptedKey);
			byte[] symmetricKey = new byte[32];
			System.arraycopy(decryptedBlock, decryptedBlock.length - symmetricKey.length, symmetricKey, 0, symmetricKey.length);
			return symmetricKey;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
			e.printStackTrace();
		}
        return null;
	}

	private static PrivateKey getPrivateKey(String fileloc, String privateKeyPassCode) {
		try {
			File f = new File(fileloc);
			InputStream fr = new FileInputStream(fileloc);
			int ivlength = fr.read();
			long length = f.length() - ivlength - 1;
			byte[] iv = new byte[ivlength];
			fr.read(iv);

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(privateKeyPassCode.getBytes("UTF-8"));
			byte[] passcode = md.digest();

			ByteArrayOutputStream bout = new ByteArrayOutputStream();

			StreamCipher cipher = new Salsa20Engine();
			cipher.init(false, new ParametersWithIV(new KeyParameter(passcode), iv));
			CipherOutputStream symOut = new CipherOutputStream(bout, cipher);

			byte[] buffer = new byte[2048];
			long bytesRead = 0;
			while (bytesRead < length) {
				int read = fr.read(buffer);
				symOut.write(buffer, 0, read);
				bytesRead += read;
			}
			CharArrayReader r = new CharArrayReader(new String(bout.toByteArray()).toCharArray());
			PemReader pempublic = new PemReader(r);
			byte[] bytes = pempublic.readPemObject().getContent();
			PrivateKey pub = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
			pempublic.close();
			return pub;

		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
