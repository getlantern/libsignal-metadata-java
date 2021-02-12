package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.InvalidKeyException;

public class ProtocolInvalidKeyException extends ProtocolException {
  public ProtocolInvalidKeyException(InvalidKeyException e, byte[] sender, byte[] senderDevice) {
    super(e, sender, senderDevice);
  }
}
