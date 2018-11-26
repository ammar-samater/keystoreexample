package sample;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class MyKeyStore {

	/**
	 * Performs the signing action on a given string
	 * 
	 * @param plainText
	 *            the string that is being signed
	 * @return the signed string
	 * @throws GeneralSecurityException
	 */
	public static String signString(String plainText, PrivateKey privateKey) throws GeneralSecurityException {

		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(plainText.getBytes(UTF_8));
		byte[] signature = privateSignature.sign();

		return Base64.getEncoder().encodeToString(signature);

	}

	/**
	 * Authenticates the plain text against the received signature
	 * 
	 * @param plainText
	 *            the string that is being verified
	 * @param signature
	 *            the signed string
	 * @param publicKey the public key
	 * 
	 * @return true if the plain text is authentic
	 * @throws GeneralSecurityException
	 */

	public static boolean verifySignedString(String plainText, String signature, PublicKey publicKey)
			throws GeneralSecurityException {

		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(UTF_8));

		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		return publicSignature.verify(signatureBytes);
	}

}
