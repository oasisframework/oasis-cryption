package io.github.oasisframework.cryption;

import io.github.oasisframework.cryption.domain.RSAEntity;
import io.github.oasisframework.data.conversion.StringUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.StringJoiner;
import java.util.regex.Pattern;

@NoArgsConstructor (access = AccessLevel.PRIVATE)
public final class RSAEncryption {
	private static final String KEY_TYPE_RSA = "RSA";
	private static final String ALGORITHM_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	private static final String PAGE_DELIMITER = "|";
	private static final Pattern PAGE_DELIMITER_PATTERN = Pattern.compile("\\|");
	private static final int KEY_SIZE = 2048;
	private static final int PAGE_SIZE = 100;

	public static RSAEntity encrypt(String plainText) {
		try {
			RSAEntity entity = createRSAEntityWithKeyPair();
			entity.addPlainText(plainText, PAGE_SIZE);

			StringJoiner joiner = new StringJoiner(PAGE_DELIMITER);
			entity.getPlainTextParts().stream().map(textPart -> getEncryptedPage(textPart, entity)).forEachOrdered(joiner::add);

			entity.setEncryptedText(Base64.getEncoder().encodeToString(joiner.toString().getBytes(StandardCharsets.UTF_8)));

			return entity;
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	private static String getEncryptedPage(String plainText, RSAEntity entity) {
		try {
			Cipher encryptCipher = Cipher.getInstance(ALGORITHM_RSA);
			encryptCipher.init(Cipher.ENCRYPT_MODE, entity.getPublicKey());
			byte[] encryptedTextBytes = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(encryptedTextBytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
				 BadPaddingException e) {
			throw new CrypticException(e);
		}
	}

	public static String decrypt(String encodedPrivateKey, String encoded) {
		try {
			PrivateKey privateKey = getPrivateKeyFromEncoded(encodedPrivateKey);
			String semiDecoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
			if (PAGE_DELIMITER_PATTERN.matcher(semiDecoded).find()) {
				StringBuilder decryptedBuilder = new StringBuilder();
				PAGE_DELIMITER_PATTERN.splitAsStream(semiDecoded).map(part -> getDecryptedPage(privateKey, part))
						.forEachOrdered(decryptedBuilder::append);
				return decryptedBuilder.toString();
			} else {
				return getDecryptedPage(privateKey, semiDecoded);
			}
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			return null;
		}
	}

	private static String getDecryptedPage(PrivateKey privateKey, String encodedPart) {
		try {
			Cipher decryptCipher = Cipher.getInstance(ALGORITHM_RSA);

			decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedTextBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encodedPart));

			return new String(decryptedTextBytes, StandardCharsets.UTF_8);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
				 BadPaddingException e) {
			throw new CrypticException(e);
		}
	}

	public static RSAEntity createRSAEntityWithKeyPair() throws NoSuchAlgorithmException {
		KeyPair pair = createRSAKeyPair();
		PublicKey publicKey = pair.getPublic();
		PrivateKey privateKey = pair.getPrivate();
		String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		String encodedPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		return RSAEntity.builder().publicKey(publicKey).privateKey(privateKey).encodedPublicKey(encodedPublicKey)
				.encodedPrivateKey(encodedPrivateKey).build();
	}

	public static KeyPair createRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_TYPE_RSA);
		generator.initialize(KEY_SIZE);
		return generator.generateKeyPair();
	}

	public static PrivateKey getPrivateKeyFromEncoded(String encoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_TYPE_RSA);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded));
		return keyFactory.generatePrivate(privateKeySpec);
	}

}
