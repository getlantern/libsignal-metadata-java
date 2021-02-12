package org.signal.libsignal.metadata;


public class ProtocolDuplicateMessageException extends ProtocolException {
  public ProtocolDuplicateMessageException(Exception e, byte[] sender, byte[] senderDevice) {
    super(e, sender, senderDevice);
  }
}
