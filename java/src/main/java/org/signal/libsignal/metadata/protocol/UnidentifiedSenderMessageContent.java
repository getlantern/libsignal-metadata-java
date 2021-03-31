package org.signal.libsignal.metadata.protocol;


import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.SignalProtos;
import org.whispersystems.libsignal.DeviceId;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;

public class UnidentifiedSenderMessageContent {

  private final int    type;
  private final byte[] senderIdentityKey;
  private final byte[] senderDeviceId;
  private final byte[] content;
  private final byte[] serialized;

  public UnidentifiedSenderMessageContent(byte[] serialized) throws InvalidMetadataMessageException {
    try {
      SignalProtos.UnidentifiedSenderMessage.Message message = SignalProtos.UnidentifiedSenderMessage.Message.parseFrom(serialized);

      if (!message.hasType() || !message.hasSenderIdentity() || !message.hasSenderDeviceId() || !message.hasContent()) {
        throw new InvalidMetadataMessageException("Missing fields");
      }

      switch (message.getType()) {
        case MESSAGE:        this.type = CiphertextMessage.WHISPER_TYPE;        break;
        case PREKEY_MESSAGE: this.type = CiphertextMessage.PREKEY_TYPE;         break;
        default:             throw new InvalidMetadataMessageException("Unknown type: " + message.getType().getNumber());
      }

      this.senderIdentityKey = message.getSenderIdentity().toByteArray();
      this.senderDeviceId = message.getSenderDeviceId().toByteArray();
      this.content        = message.getContent().toByteArray();
      this.serialized     = serialized;
    } catch (InvalidProtocolBufferException e) {
      throw new InvalidMetadataMessageException(e);
    }
  }

  public UnidentifiedSenderMessageContent(int type, byte[] senderIdentityKey, byte[] senderDeviceId, byte[] content) {
    this.serialized = SignalProtos.UnidentifiedSenderMessage.Message.newBuilder()
                                                                    .setType(SignalProtos.UnidentifiedSenderMessage.Message.Type.valueOf(getProtoType(type)))
                                                                    .setSenderIdentity(ByteString.copyFrom(senderIdentityKey))
                                                                    .setSenderDeviceId(ByteString.copyFrom(senderDeviceId))
                                                                    .setContent(ByteString.copyFrom(content))
                                                                    .build()
                                                                    .toByteArray();

    this.type = type;
    this.senderIdentityKey = senderIdentityKey;
    this.senderDeviceId = senderDeviceId;
    this.content = content;
  }

  public int getType() {
    return type;
  }

  /**
   * WARNING - for inbound messages, this sender identity key is just whatever the sender included
   * in their message, it has not been verified yet. During decryption, if this address doesn't
   * match the one that encrypted the message, the MAC check will fail.
   * @return
   */
  public byte[] getSenderIdentityKey() {
    return senderIdentityKey;
  }

  public byte[] getSenderDeviceId() {
    return senderDeviceId;
  }

  /**
   * WARNING - for inbound messages, this address is just whatever the sender included in their
   * message, it has not been verified yet. During decryption, if this address doesn't match the one
   * that encrypted the message, the MAC check will fail.
   * @return
   */
  public SignalProtocolAddress getSenderAddress() throws InvalidKeyException {
    return new SignalProtocolAddress(new ECPublicKey(senderIdentityKey), new DeviceId(senderDeviceId));
  }

  public byte[] getContent() {
    return content;
  }

  public byte[] getSerialized() {
    return serialized;
  }

  private int getProtoType(int type) {
    switch (type) {
      case CiphertextMessage.WHISPER_TYPE: return SignalProtos.UnidentifiedSenderMessage.Message.Type.MESSAGE_VALUE;
      case CiphertextMessage.PREKEY_TYPE:  return SignalProtos.UnidentifiedSenderMessage.Message.Type.PREKEY_MESSAGE_VALUE;
      default:                             throw new AssertionError(type);
    }
  }

}
