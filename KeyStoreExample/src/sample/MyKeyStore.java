package sample;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * The MyKeyStore provides two functionalities. 1. Generate a digital signature
 * 2. Verify a digital signature
 * 
 * The signature algorithm used is SHA256withRSA
 * 
 * @author Ammar Samater @
 */
public class MyKeyStore {

	/**
	 * Performs the signing action on a given string
	 * 
	 * @param plainText
	 *            the string that is being signed
	 * @param privateKey
	 *            the private key to sign with
	 * @param algorithem
	 *            the signature algorithm
	 * @return the signed string
	 * @throws NoSuchAlgorithmException
	 *             This exception is thrown when a particular cryptographic
	 *             algorithm is requested but is not available in the environment.
	 * @throws InvalidKeyException
	 *             This is the exception for invalid Keys (invalid encoding, wrong
	 *             length, uninitialized, etc).
	 * @throws SignatureException
	 *             generic exception class for all the security related exceptions
	 * 
	 */
	public static String signString(String plainText, PrivateKey privateKey, String algorithem)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature privateSignature = Signature.getInstance(algorithem);
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
	 * @param publicKey
	 *            the public key
	 * @param algorithem
	 *            the signature algorithm
	 * 
	 * @return true if the plain text is authentic
	 * @throws NoSuchAlgorithmException
	 *             This exception is thrown when a particular cryptographic
	 *             algorithm is requested but is not available in the environment.
	 * @throws InvalidKeyException
	 *             This is the exception for invalid Keys (invalid encoding,
	 *             wrong length, uninitialized, etc).
	 * @throws SignatureException
	 *             This is the generic Signature exception.
	 */
	public static boolean isVerified(String plainText, String signature, PublicKey publicKey, String algorithem)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature publicSignature = Signature.getInstance(algorithem);
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(UTF_8));

		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		return publicSignature.verify(signatureBytes);
	}

}
