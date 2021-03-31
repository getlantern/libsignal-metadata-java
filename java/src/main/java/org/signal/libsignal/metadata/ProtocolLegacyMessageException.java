package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.LegacyMessageException;

public class ProtocolLegacyMessageException extends ProtocolException {
  public ProtocolLegacyMessageException(LegacyMessageException e, byte[] sender, byte[] senderDeviceId) {
    super(e, sender, senderDeviceId);
  }
}
