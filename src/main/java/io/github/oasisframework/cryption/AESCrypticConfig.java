package io.github.oasisframework.cryption;

import io.github.oasisframework.data.conversion.StringUtils;

import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;


final class AESCrypticConfig {
	private static final int KEY_LENGTH = 256;
	private static final int ITERATION_COUNT = 65536;
	private static final String AES = "AES";
	private static final String SHA_256 = "PBKDF2WithHmacSHA256";
	private static final String TRANSFORMATION = "AES/GCM/PKCS5PADDING";
	private static final String DESIRED_ENCRYPT = "GCM";
	private static final String DEFAULT_ENCRYPT = "CBC";
	private static final String FILE_NAME = "AESCrypterConfig.json";
	private static final String BOUNCY_CASTLE_PROVIDER = "BC";

	private static final String KEY_HOLDER = "key";
	private static final String INIT_VECTOR_HOLDER = "initVector";

	static String DEFAULT_KEY;
	static IvParameterSpec ivParameterSpec;
	private static final SecretKeySpec secretKeySpec;

	static {
		try (InputStream inputStream = new ClassPathResource(FILE_NAME).getInputStream()) {
			JSONObject obj = new JSONObject(new JSONTokener(inputStream));

			DEFAULT_KEY = obj.optString(KEY_HOLDER);
			String initVector = obj.optString(INIT_VECTOR_HOLDER);

			if (StringUtils.isBlank(DEFAULT_KEY) || StringUtils.isBlank(initVector)) {
				throw new RuntimeException("Init vector not found!");
			}

			ivParameterSpec = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
			secretKeySpec = new SecretKeySpec(DEFAULT_KEY.getBytes(StandardCharsets.UTF_8), AES);
		} catch (Exception e) {
			throw new RuntimeException("Encryption config cannot be loaded, please check encryption vector files.");
		}
	}

	static Cipher createCipher(String encryption, int mode)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			NoSuchProviderException {
		Cipher cipher = getCipher(encryption);
		cipher.init(mode, getSecretKeySpec(), getIvParameterSpec());

		return cipher;
	}

	static Cipher createCyberCipher(int mode, SecretKeySpec secretKeySpec, IvParameterSpec ivSpec)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance(getTransformation(null));
		cipher.init(mode, secretKeySpec, ivSpec);
		return cipher;
	}

	static SecretKeySpec createSecretKeySpec(String secret, String salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(SHA_256);
		KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), AESCrypticConfig.ITERATION_COUNT,
				AESCrypticConfig.KEY_LENGTH);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), AES);
	}

	private static Cipher getCipher(String encryption)
			throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
		if (StringUtils.isBlank(encryption) || DEFAULT_ENCRYPT.equals(encryption)) {
			return Cipher.getInstance(getTransformation(encryption));
		}

		return Cipher.getInstance(getTransformation(encryption), BOUNCY_CASTLE_PROVIDER);
	}

	private static IvParameterSpec getIvParameterSpec() {
		return ivParameterSpec;
	}

	private static SecretKeySpec getSecretKeySpec() {
		return secretKeySpec;
	}

	private static String getTransformation(String encryption) {
		return TRANSFORMATION.replaceAll(DESIRED_ENCRYPT, getEncryption(encryption));
	}

	private static String getEncryption(String encryption) {
		if (StringUtils.isBlank(encryption)) {
			return DEFAULT_ENCRYPT;
		}

		return encryption;
	}


}
