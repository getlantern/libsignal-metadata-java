package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.InvalidMessageException;

public class ProtocolInvalidMessageException extends ProtocolException {
  public ProtocolInvalidMessageException(InvalidMessageException e, byte[] sender, byte[] senderDevice) {
    super(e, sender, senderDevice);
  }
}
