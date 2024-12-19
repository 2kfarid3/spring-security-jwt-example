package org.example.springsecurityjwtexample.ecxeption;

public class AlreadyExistsException extends RuntimeException {
    public AlreadyExistsException(String message) {
        super(message);
    }
}
