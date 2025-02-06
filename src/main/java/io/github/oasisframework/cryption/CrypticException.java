package io.github.oasisframework.cryption;

public class CrypticException extends RuntimeException{
	public CrypticException(Throwable wrappedException) {
		super(wrappedException);
	}
}
