package io.github.oasisframework.cryption.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RSAEntity {
	private String plainText;
	private List<String> plainTextParts;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private String encodedPublicKey;
	private String encodedPrivateKey;
	private String encryptedText;

	public void addPlainText(String plainText, int size) {
		this.plainText = plainText;
		plainTextParts = splitEqually(plainText, size);
	}

	private List<String> splitEqually(String text, int size) {
		List<String> ret = new ArrayList<>((text.length() + size - 1) / size);

		for (int start = 0; start < text.length(); start += size) {
			ret.add(text.substring(start, Math.min(text.length(), start + size)));
		}
		return ret;
	}
}
