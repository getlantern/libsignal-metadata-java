package org.signal.libsignal.metadata;


public class ProtocolInvalidKeyIdException extends ProtocolException {
  public ProtocolInvalidKeyIdException(Exception e, byte[] sender, byte[] senderDevice) {
    super(e, sender, senderDevice);
  }
}
