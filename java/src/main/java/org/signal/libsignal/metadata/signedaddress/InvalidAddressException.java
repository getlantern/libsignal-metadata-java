package org.signal.libsignal.metadata.signedaddress;


public class InvalidAddressException extends Exception {
  public InvalidAddressException(String s) {
    super(s);
  }

  public InvalidAddressException(Exception e) {
    super(e);
  }
}
