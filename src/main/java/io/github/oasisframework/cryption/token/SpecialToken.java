package io.github.oasisframework.cryption.token;

import io.github.oasisframework.cryption.AESCrypt;
import io.github.oasisframework.cryption.AESDecrypt;
import io.github.oasisframework.data.conversion.StringUtils;
import io.github.oasisframework.data.conversion.response.JsonUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SpecialToken {
	private static final int SPECIAL_KEY_BEGINNING_INDEX = 0;
	private static final int SPECIAL_KEY_LENGTH = 10;

	private static final long NOT_EXPIRED = -1L;

	private static final int FRESHNESS_INDEX = 0;
	private static final int CONTEXT_INDEX = 1;
	private static final int PRIVATE_KEY_INDEX = 2;
	private static final int SPECIAL_KEY_INDEX = 3;
	private static final int SPECIAL_TOKEN_PARTS_SIZE = 4;

	private static final String SPECIAL_TOKEN_DELIMITER = "\\.";
	private static final Pattern SPECIAL_TOKEN_PATTERN = Pattern.compile(SPECIAL_TOKEN_DELIMITER);

	/**
	 * The first part is freshness payload,
	 * the second part is payload with msisdn,
	 * the third part is encrypted and encoded  private key,
	 * the last part is special key for msisdn
	 */
	private static final String PUBLIC_ROOT_HANDSHAKE_TEMPLATE = "%s.%s.%s.%s";
	private static final String TOKEN_EXPIRES_KEY = "expires_at";
	private static final String COMPLEXITY_KEY = "custom_token";

	private String payloadJson;
	private String plainSpecialKey;
	private String encodedSpecialKey;
	private String encodedToken;

	public static <T> SpecialToken encrypt(T payloadValue, String plainSpecialKey, long expiringBufferAsHours) {
		String payloadJson = JsonUtil.objectToJson(payloadValue);
		SpecialToken specialToken = SpecialToken.builder().payloadJson(payloadJson).plainSpecialKey(plainSpecialKey).build();
		specialToken.setEncodedSpecialToken(expiringBufferAsHours);
		return specialToken;
	}

	public static <T> SpecialToken decrypt(String encodedToken, long expiringBufferAsHours) {
		SpecialToken specialToken = SpecialToken.builder().encodedToken(encodedToken).build();
		specialToken.decryptToken(expiringBufferAsHours);
		return specialToken;
	}

	private void decryptToken(long expiringBufferAsHours) {
		if (StringUtils.isBlank(encodedToken) || !SPECIAL_TOKEN_PATTERN.matcher(encodedToken).find()) {
			return;
		}

		List<String> keyParts = SPECIAL_TOKEN_PATTERN.splitAsStream(encodedToken).collect(Collectors.toList());
		if (keyParts.size() != SPECIAL_TOKEN_PARTS_SIZE || !isFreshToken(keyParts, expiringBufferAsHours)) {
			return;
		}
		Long expirationTime = getExpirationTime(keyParts);
		if (expirationTime == null) {
			return;
		}

		String decryptedPrivateKey = decryptPrivateKey(expirationTime, keyParts.get(PRIVATE_KEY_INDEX));
		payloadJson = decryptPayload(keyParts.get(CONTEXT_INDEX), expirationTime, decryptedPrivateKey);
		encodedSpecialKey = keyParts.get(SPECIAL_KEY_INDEX);
	}

	private String decryptPayload(String payload, long expirationTime, String privateKey) {
		String firstIterationOfPayload = AESDecrypt.decryptWithSecret(payload, privateKey, String.valueOf(expirationTime));
		return AESDecrypt.decrypt(firstIterationOfPayload);
	}

	private String decryptPrivateKey(long expirationTime, String privateKey) {
		String firstStepKey = AESDecrypt.decryptWithSecret(privateKey, String.valueOf(expirationTime));
		return AESDecrypt.decrypt(firstStepKey);
	}

	private void setEncodedSpecialToken(long expiringBufferAsHours) {
		long expirationTime = createExpirationTime(expiringBufferAsHours);
		String privateKey = UUID.randomUUID().toString();
		String payload = encryptPayload(expirationTime, privateKey);

		encodedSpecialKey = AESCrypt.encrypt(plainSpecialKey).substring(SPECIAL_KEY_BEGINNING_INDEX, SPECIAL_KEY_LENGTH);
		encodedToken = String.format(PUBLIC_ROOT_HANDSHAKE_TEMPLATE, createFreshnessPayload(expirationTime), payload,
				encryptPrivateKey(expirationTime, privateKey), encodedSpecialKey);
	}

	private String encryptPayload(long expirationTime, String privateKey) {
		String firstIterationOfPayload = AESCrypt.encrypt(payloadJson);
		return AESCrypt.encryptWithSecret(firstIterationOfPayload, privateKey, String.valueOf(expirationTime));
	}

	private String encryptPrivateKey(long expirationTime, String privateKey) {
		String firstStepKey = AESCrypt.encrypt(privateKey);
		return AESCrypt.encryptWithSecret(firstStepKey, String.valueOf(expirationTime));
	}

	private String createFreshnessPayload(long expirationTime) {
		Map<String, String> freshnessPart = new HashMap<>();

		freshnessPart.put(TOKEN_EXPIRES_KEY, String.valueOf(expirationTime));
		freshnessPart.put(COMPLEXITY_KEY, UUID.randomUUID().toString());

		String json = JsonUtil.objectToJson(freshnessPart);

		return AESCrypt.encrypt(json);
	}

	private long createExpirationTime(long expiringBufferAsHours) {
		if (NOT_EXPIRED == expiringBufferAsHours) {
			return NOT_EXPIRED;
		}

		return ZonedDateTime.now().plusHours(expiringBufferAsHours).toInstant().toEpochMilli();
	}

	private boolean isFreshToken(List<String> keyParts, long expiringBufferAsHours) {
		if (expiringBufferAsHours == NOT_EXPIRED) {
			return true;
		}
		Long epochMilliTimeForThreshold = getExpirationTime(keyParts);
		if (epochMilliTimeForThreshold == null) {
			return false;
		}
		return epochMilliTimeForThreshold == NOT_EXPIRED || Instant.now()
				.isBefore(Instant.ofEpochMilli(epochMilliTimeForThreshold));
	}

	@SuppressWarnings ({ "unchecked" })
	private Long getExpirationTime(List<String> keyParts) {
		String freshnessPart = keyParts.get(FRESHNESS_INDEX);
		if (StringUtils.isBlank(freshnessPart)) {
			return null;
		}
		String json = AESDecrypt.decrypt(freshnessPart);
		Map<String, String> freshnessMap = JsonUtil.jsonToObject(json, HashMap.class);
		if (CollectionUtils.isEmpty(freshnessMap) || !freshnessMap.containsKey(TOKEN_EXPIRES_KEY)) {
			return null;
		}
		return Long.parseLong(freshnessMap.get(TOKEN_EXPIRES_KEY));
	}
}
