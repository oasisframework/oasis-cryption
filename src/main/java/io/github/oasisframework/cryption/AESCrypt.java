package io.github.oasisframework.cryption;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static io.github.oasisframework.data.conversion.StringUtils.isBlank;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AESCrypt {

	public static String encrypt(String value) {
		return encrypt(value, null);
	}

	public static String encrypt(String value, String encryption) {
		if (isBlank(value)) {
			return null;
		}

		try {
			byte[] encrypted = AESCrypticConfig.createCipher(encryption, Cipher.ENCRYPT_MODE).doFinal(value.getBytes());

			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception e) {
			return null;
		}
	}

	public static String encryptWithSecret(String plainText, String salt) {
		return encryptWithSecret(plainText, AESCrypticConfig.DEFAULT_KEY, salt);
	}

	public static String encryptWithSecret(String plainText, String secret, String salt) {
		try {
			byte[] iv = new byte[16];
			Cipher cipher = AESCrypticConfig.createCyberCipher(Cipher.ENCRYPT_MODE,
					AESCrypticConfig.createSecretKeySpec(secret, salt), createIvParamSpecForCBC(iv));
			byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] encryptedData = new byte[iv.length + cipherText.length];
			System.arraycopy(iv, 0, encryptedData, 0, iv.length);
			System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

			return Base64.getEncoder().encodeToString(encryptedData);
		} catch (Exception e) {
			return null;
		}
	}

	private static IvParameterSpec createIvParamSpecForCBC(byte[] iv) {
		SecureRandom secureRandom = new SecureRandom();

		secureRandom.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
}
