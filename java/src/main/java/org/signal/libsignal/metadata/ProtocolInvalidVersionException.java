package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.InvalidVersionException;

public class ProtocolInvalidVersionException extends ProtocolException {
  public ProtocolInvalidVersionException(InvalidVersionException e, byte[] sender, byte[] senderDevice) {
    super(e, sender, senderDevice);
  }
}
