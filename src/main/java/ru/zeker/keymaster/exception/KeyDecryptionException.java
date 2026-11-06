package ru.zeker.keymaster.exception;

public class KeyDecryptionException extends KeyMasterException {

    public KeyDecryptionException() {
        super(ErrorCode.KEY_DECRYPTION_FAILED);
    }

    public KeyDecryptionException(Throwable cause) {
        super(ErrorCode.KEY_DECRYPTION_FAILED, cause);
    }
}