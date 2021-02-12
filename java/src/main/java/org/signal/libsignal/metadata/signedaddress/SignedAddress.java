package org.signal.libsignal.metadata.signedaddress;


import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.signal.libsignal.metadata.SignalProtos;
import org.signal.libsignal.metadata.encoding.UserId;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * SignedAddress represents the address of userId + deviceId with a signature from the user
 * confirming its authenticity. The userId is also the public key with which the signature was
 * generated, so the address can be authenticated without needing an external authority.
 */
public class SignedAddress {

  private final byte[] serialized;
  private final byte[] signature;
  private final byte[] userId; // 64 bytes
  private final int deviceId;

  /**
   * Constructs a new SignedAddress from its serialized representation. It verifies the address
   * against the attached signature.
   *
   * @param serialized
   * @throws InvalidAddressException if there was a problem deserializing the address
   * @throws InvalidKeyException if the address's signature doesn't match what's expected based on using the userId as the public key
   */
  public SignedAddress(byte[] serialized) throws InvalidAddressException, InvalidKeyException {
    try {
      SignalProtos.SignedAddress wrapper = SignalProtos.SignedAddress.parseFrom(serialized);

      if (!wrapper.hasSignature() || !wrapper.hasAddress()) {
        throw new InvalidAddressException("Missing fields");
      }

      SignalProtos.SignedAddress.Address address = SignalProtos.SignedAddress.Address.parseFrom(wrapper.getAddress());

      if (!address.hasUserId() || !address.hasDeviceId()) {
        throw new InvalidAddressException("Missing fields");
      }

      this.userId   = address.getUserId().toByteArray();
      this.deviceId = address.getDeviceId();

      this.serialized  = serialized;
      this.signature   = wrapper.getSignature().toByteArray();

      // Using the userId as the public key, verify that the signature matches what's expected
      ECPublicKey publicKey = UserId.keyFrom(this.userId);
      if (!Curve.verifySignature(publicKey, address.toByteArray(), this.signature)) {
        throw new InvalidAddressException("signature verification failed");
      };
    } catch (InvalidProtocolBufferException | InvalidKeyException e) {
      throw new InvalidAddressException(e);
    }
  }

  /**
   * Constructs a new SignedAddress using the component userId, deviceId and signing it with
   * the provided signingKey.
   *
   * @param userId the user's unique ID (also their public key)
   * @param deviceId the user's device ID (actually a uint32)
   * @param signingKey the private key corresponding to the user's ID, used to sign the address
   * @throws InvalidKeyException
   */
  public SignedAddress(byte[] userId, int deviceId, ECPrivateKey signingKey) throws InvalidKeyException {
    byte[] address = SignalProtos.SignedAddress.Address.newBuilder()
            .setUserId(ByteString.copyFrom(userId))
            .setDeviceId(deviceId)
            .build().toByteArray();
    this.signature = Curve.calculateSignature(signingKey, address);
    this.serialized = SignalProtos.SignedAddress.newBuilder()
            .setAddress(ByteString.copyFrom(address))
            .setSignature(ByteString.copyFrom(this.signature))
            .build().toByteArray();
    this.userId = userId;
    this.deviceId = deviceId;
  }

  public byte[] getSerialized() {
    return serialized;
  }

  public byte[] getUserId() {
    return userId;
  }

  public String getSender() {
    return UserId.encodeToString(userId);
  }

  public int getSenderDeviceId() {
    return deviceId;
  }

  public SignalProtocolAddress getSenderAddress() {
    return new SignalProtocolAddress(getSender(), deviceId);
  }
}
