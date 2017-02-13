package net.sourceforge.opencamera.Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
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
		} catch (IOException e) {
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
        	Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
			rsaCipher.init(Cipher.DECRYPT_MODE, privatekey);
			byte[] keyWithPadding = rsaCipher.doFinal(key);
			byte[] res = new byte[32];
			System.arraycopy(keyWithPadding, keyWithPadding.length - 32, res, 0, 32);
			return res;
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
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
