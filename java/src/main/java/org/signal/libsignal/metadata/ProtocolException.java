package org.signal.libsignal.metadata;


public abstract class ProtocolException extends Exception {

  private final byte[] sender;
  private final byte[] senderDevice;

  public ProtocolException(Exception e, byte[] sender, byte[] senderDevice) {
    super(e);
    this.sender       = sender;
    this.senderDevice = senderDevice;
  }

  public byte[] getSender() {
    return sender;
  }

  public byte[] getSenderDevice() {
    return senderDevice;
  }
}
