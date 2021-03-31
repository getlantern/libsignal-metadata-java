package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.NoSessionException;

public class ProtocolNoSessionException extends ProtocolException {
  public ProtocolNoSessionException(NoSessionException e, byte[] sender, byte[] senderDevice) {
    super(e, sender, senderDevice);
  }
}
