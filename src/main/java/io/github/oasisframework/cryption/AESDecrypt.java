package io.github.oasisframework.cryption;

import io.github.oasisframework.data.conversion.StringUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AESDecrypt {
	public static String decrypt(String encrypted) {
		return decrypt(encrypted, null);
	}

	public static String decrypt(String encrypted, String encryption) {
		if (StringUtils.isBlank(encrypted)) {
			return null;
		}
		try {
			byte[] original = AESCrypticConfig.createCipher(encryption, Cipher.DECRYPT_MODE).doFinal(Base64.getDecoder().decode(encrypted));

			return new String(original);
		} catch (Exception e) {
			return null;
		}
	}

	public static String decryptWithSecret(String encrypted, String salt) {
		return decryptWithSecret(encrypted, AESCrypticConfig.DEFAULT_KEY, salt);
	}

	public static String decryptWithSecret(String encrypted, String secret, String salt) {
		try {
			byte[] iv = new byte[16];
			byte[] encryptedData = Base64.getDecoder().decode(encrypted);

			Cipher cipher = AESCrypticConfig.createCyberCipher(Cipher.DECRYPT_MODE,
					AESCrypticConfig.createSecretKeySpec(secret, salt), createIvParamSpecForCBC(iv, encryptedData));
			byte[] cipherText = new byte[encryptedData.length - 16];
			System.arraycopy(encryptedData, 16, cipherText, 0, cipherText.length);

			byte[] decryptedText = cipher.doFinal(cipherText);
			return new String(decryptedText, StandardCharsets.UTF_8);
		} catch (Exception e) {
			return null;
		}
	}

	private static IvParameterSpec createIvParamSpecForCBC(byte[] iv, byte[] encryptedData) {
		System.arraycopy(encryptedData, 0, iv, 0, iv.length);
		return new IvParameterSpec(iv);
	}
}
