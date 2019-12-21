package sample;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

public class Main {
	
	//Don't forget to create the key store first!

	public static void main(String[] args) {
		String string = "Attackers might be trying to steal your information from www.google.com (for example, passwords, messages, or credit cards";
		
		try {
			KeyPair keyPair = getKeyPairFromKeyStore("/mykeystore.jks", "JKS", "mystorepassword".toCharArray(), "mykeypassword".toCharArray(), "testkey");

			String signedString = MyKeyStore.signString(string, keyPair.getPrivate(), "SHA256withRSA");
			System.out.println(signedString);

			boolean isVerfied = MyKeyStore.isVerified(string, signedString, keyPair.getPublic(), "SHA256withRSA");
			System.out.println("isVerfied = " + isVerfied);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	private static KeyPair getKeyPairFromKeyStore(String keyStorePath, String keyStoreType, char[] keyStorePassword, char[] keyPassword, String keyAlias) throws NoSuchAlgorithmException, CertificateException, IOException,
			KeyStoreException, UnrecoverableEntryException {

		InputStream ins = KeyStore.class.getResourceAsStream(keyStorePath);
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(ins, keyStorePassword);
		KeyStore.PasswordProtection protectedPassword = new KeyStore.PasswordProtection(keyPassword); 
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, protectedPassword);
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();

		java.security.cert.Certificate cert = keyStore.getCertificate(keyAlias);
		PublicKey publicKey = cert.getPublicKey();

		return new KeyPair(publicKey, privateKey);

	}
}
