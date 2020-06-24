package com.finger.tsa.common.advice;

import lombok.Getter;

public class FchainException extends Exception {

	private static final long serialVersionUID = 1164781449316312284L;

	@Getter
	private int code;
	@Getter
	private String message;
	@Getter
	private Exception exception;

	public FchainException( int code, Exception exception ) {

		this.code      = code;
		this.exception = exception;
	}
	public FchainException( int code, String message) {
		this.code = code;
		this.message = message;
	}
}
