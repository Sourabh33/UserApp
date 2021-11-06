package com.library.UserApp.exception;

public class JwtAuthException extends Exception {
    public JwtAuthException(String message, Exception e) {
        super(message, e);
    }
}
