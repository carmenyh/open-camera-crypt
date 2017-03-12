package net.sourceforge.opencamera.Crypto;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Environment;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.io.FileReader;


import org.spongycastle.util.io.pem.PemReader;

import static android.content.ContentValues.TAG;

public class AsymmetricKeyReader {
    static PublicKey readKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            PemReader pempublic = new PemReader(new FileReader(new File(filename)));
            byte[] bytes = pempublic.readPemObject().getContent();
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
            pempublic.close();
            return pub;
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
