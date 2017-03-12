package net.sourceforge.opencamera.Crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.spongycastle.crypto.InvalidCipherTextException;

public class MoreCryptoTests {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidCipherTextException {
		testFullLife("C:\\Users\\jafre\\Desktop\\priv.pem", "C:\\Users\\jafre\\Desktop\\pub.pem", "C:\\Users\\jafre\\Desktop\\other.jpg", "C:\\Users\\jafre\\Desktop\\test2.jpg");
	}

	private static void testFullLife(String privateLoc, String publicLoc, String inputFile, String outputFile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, InvalidCipherTextException {
		String midFile = "C:\\Users\\jafre\\Desktop\\test2.jpg.encrypted";
		iesTest(publicLoc, inputFile, midFile);

		String[] args = {privateLoc, midFile, outputFile};
		Decryptor.main(args);
	}

	private static void iesTest(String publicLoc, String inputFile, String midFile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, InvalidCipherTextException {
		PublicKey pub = AsymmetricKeyReader.readKey(publicLoc);
		ImageEncryptionStream ies = new ImageEncryptionStream(pub, new FileOutputStream(midFile));
		ies.init();
        File file = new File(inputFile);
        FileInputStream fileStream = new FileInputStream(file);

        // Instantiate array
        byte[] arr = new byte[(int)file.length()];

        /// read All bytes of File stream
        fileStream.read(arr,0,arr.length);

		ies.write(arr);
		ies.flush();
		ies.close();
	}
}
