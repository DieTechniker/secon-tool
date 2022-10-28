package de.tk.opensource.secon;

public class CertificateVerificationException extends SeconException {

    public CertificateVerificationException(Exception e) {
    	super(e);
	}

	public CertificateVerificationException(String message, Throwable cause) {
		super(message, cause);
	}

	public CertificateVerificationException(String message) {
		super(message);
	}

	private static final long serialVersionUID = 0L;

    
}
