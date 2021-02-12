package org.signal.libsignal.metadata.protocol;


import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.SignalProtos;
import org.signal.libsignal.metadata.signedaddress.InvalidAddressException;
import org.signal.libsignal.metadata.signedaddress.SignedAddress;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.protocol.CiphertextMessage;

public class UnidentifiedSenderMessageContent {

  private final int               type;
  private final SignedAddress signedAddress;
  private final byte[]            content;
  private final byte[]            serialized;

  public UnidentifiedSenderMessageContent(byte[] serialized) throws InvalidMetadataMessageException, InvalidAddressException, InvalidKeyException {
    try {
      SignalProtos.UnidentifiedSenderMessage.Message message = SignalProtos.UnidentifiedSenderMessage.Message.parseFrom(serialized);

      if (!message.hasType() || !message.hasSignedSenderAddress() || !message.hasContent()) {
        throw new InvalidMetadataMessageException("Missing fields");
      }

      switch (message.getType()) {
        case MESSAGE:        this.type = CiphertextMessage.WHISPER_TYPE;        break;
        case PREKEY_MESSAGE: this.type = CiphertextMessage.PREKEY_TYPE;         break;
        default:             throw new InvalidMetadataMessageException("Unknown type: " + message.getType().getNumber());
      }

      this.signedAddress = new SignedAddress(message.getSignedSenderAddress().toByteArray());
      this.content           = message.getContent().toByteArray();
      this.serialized        = serialized;
    } catch (InvalidProtocolBufferException e) {
      throw new InvalidMetadataMessageException(e);
    }
  }

  public UnidentifiedSenderMessageContent(int type, SignedAddress signedAddress, byte[] content) {
    try {
      this.serialized = SignalProtos.UnidentifiedSenderMessage.Message.newBuilder()
                                                                      .setType(SignalProtos.UnidentifiedSenderMessage.Message.Type.valueOf(getProtoType(type)))
                                                                      .setSignedSenderAddress(SignalProtos.SignedAddress.parseFrom(signedAddress.getSerialized()))
                                                                      .setContent(ByteString.copyFrom(content))
                                                                      .build()
                                                                      .toByteArray();

      this.type = type;
      this.signedAddress = signedAddress;
      this.content = content;
    } catch (InvalidProtocolBufferException e) {
      throw new AssertionError(e);
    }
  }

  public int getType() {
    return type;
  }

  public SignedAddress getSignedAddress() {
    return signedAddress;
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
