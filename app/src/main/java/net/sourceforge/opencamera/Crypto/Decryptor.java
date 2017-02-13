package net.sourceforge.opencamera.Crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import org.spongycastle.crypto.io.CipherInputStream;
import org.spongycastle.crypto.io.CipherOutputStream;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.io.pem.PemReader;

public class Decryptor {
	public static void main(String[] args) {
		DefaultParser parser = new DefaultParser();
        Options options = new Options();
        options.addOption("s", "secret", true, "The path of the private key file to be used to decrypt the image");
        options.addOption("d", "use-directories", false, "Decrypt all encrypted photos in a directory");
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
		PrivateKey privateKey = getPrivateKey(privateKeyFilepath);

		String[] paths = commandLine.getArgs();
		if (paths.length != 2) {
			printAndExit("Incorrect number of arguments.");
		}
		File inputPath = new File(paths[1]);
		File outputPath = new File(paths[1]);

		boolean useDirs = commandLine.hasOption('d');
		if (useDirs) {
			if (!inputPath.isDirectory() || !outputPath.isDirectory()) {
				printAndExit("Input and output paths must be directories.");
			}
			File[] files = inputPath.listFiles(new FilenameFilter() {
				@Override
				public boolean accept(File dir, String name) {
					return name.endsWith(".encrypted");
				}
			});
			for (File encryptedFile : files) {
				String inFilename = encryptedFile.getName();
				String outFilename = inFilename.substring(0, inFilename.length() - ".encrypted".length());
				decryptSingleFile(privateKey, encryptedFile, new File(outputPath, outFilename));
			}
		} else {
			if (!inputPath.isFile() || !outputPath.isFile()) {
				printAndExit("Input and output paths must be files.");
			}
			decryptSingleFile(privateKey, inputPath, outputPath);
		}
	}

	private static void printAndExit(String message) {
		System.err.println(message);
		System.exit(1);
	}

	public static byte[] decryptSingleFile(PrivateKey privatekey, File fi, File fo) {
		try {
			long fileLength = fi.length();
			InputStream fr = new FileInputStream(fi);

			// Calculate the length of the various parts of the encrypted file
			int sklength = fr.read();
			int ivlength = fr.read();
			int imageLength = (int)fileLength - (sklength + ivlength + 1 + 1);

			// Read the symmetric key
			byte[] encryptedKey = new byte[sklength];
			fr.read(encryptedKey);
			byte[] key = decryptSymmetricKey(privatekey, encryptedKey);

			// Read the initialization vector
			byte[] iv = new byte[ivlength];
			fr.read(iv);

			// Read the photo bytes
			byte[] photo = new byte[imageLength];
			fr.read(photo);

			// Decrypt and write out the photo
			FileOutputStream fos = new FileOutputStream(fo);
			storeDecryptPhoto(key, iv, fos, fr, imageLength);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void storeDecryptPhoto(byte[] symKey, byte[] iv, FileOutputStream out, InputStream in, int length) throws IOException {
        StreamCipher cipher = new Salsa20Engine();
        cipher.init(false, new ParametersWithIV(new KeyParameter(symKey), iv));
        CipherOutputStream symOut = new CipherOutputStream(out, cipher);

		byte[] buffer = new byte[2048];
		long bytesRead = 0;
		while (bytesRead < length) {
			int read = in.read(buffer);
			symOut.write(buffer, 0, read);
			bytesRead += read;
		}

        symOut.close(); 
	}

	private static byte[] decryptSymmetricKey(PrivateKey privatekey, byte[] key) {
        try {
        	Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
			rsaCipher.init(Cipher.DECRYPT_MODE, privatekey);
			byte[] keyWithPadding = rsaCipher.doFinal(key);
			byte[] res = new byte[32];
			System.arraycopy(keyWithPadding, keyWithPadding.length - 32, res, 0, 32);
			return res;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
			e.printStackTrace();
		}
        return null;
	}

	public static PrivateKey getPrivateKey(String fileloc) {
		try {
			PemReader pempublic = new PemReader(new FileReader(new File(fileloc)));
			byte[] bytes = pempublic.readPemObject().getContent();
			PrivateKey pub = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
			pempublic.close();
			return pub;
		} catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
	}
}
