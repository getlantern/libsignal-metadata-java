package org.signal.libsignal.metadata;


import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessage;
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.DeviceId;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMacException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.util.ByteUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SealedSessionCipher {

  private static final String TAG = SealedSessionCipher.class.getSimpleName();

  private final SignalProtocolStore signalProtocolStore;
  private final DeviceId localDeviceId;

  public SealedSessionCipher(SignalProtocolStore signalProtocolStore,
                             DeviceId localDeviceId) {
    this.signalProtocolStore = signalProtocolStore;
    this.localDeviceId = localDeviceId;
  }

  public byte[] encrypt(SignalProtocolAddress destinationAddress, byte[] paddedPlaintext)
          throws InvalidKeyException {
    return encrypt(signalProtocolStore.getIdentityKeyPair(), destinationAddress, paddedPlaintext);
  }

  byte[] encrypt(ECKeyPair ourIdentity, SignalProtocolAddress destinationAddress, byte[] paddedPlaintext)
          throws InvalidKeyException {
    CiphertextMessage message = new SessionCipher(signalProtocolStore, destinationAddress).encrypt(paddedPlaintext);
    ECPublicKey theirIdentityKey = destinationAddress.getIdentityKey();

    ECKeyPair ephemeral = Curve.generateKeyPair();
    byte[] ephemeralSalt = ByteUtil.combine("UnidentifiedDelivery".getBytes(), theirIdentityKey.getBytes(), ephemeral.getPublicKey().getBytes());
    EphemeralKeys ephemeralKeys = calculateEphemeralKeys(theirIdentityKey, ephemeral.getPrivateKey(), ephemeralSalt);
    byte[] staticKeyCiphertext = encrypt(ephemeralKeys.cipherKey, ephemeralKeys.macKey, ourIdentity.getPublicKey().getBytes());

    byte[] staticSalt = ByteUtil.combine(ephemeralKeys.chainKey, staticKeyCiphertext);
    StaticKeys staticKeys = calculateStaticKeys(theirIdentityKey, ourIdentity.getPrivateKey(), staticSalt);
    UnidentifiedSenderMessageContent content = new UnidentifiedSenderMessageContent(message.getType(), ourIdentity.getPublicKey().getBytes(), this.localDeviceId.getBytes(), message.serialize());
    byte[] messageBytes = encrypt(staticKeys.cipherKey, staticKeys.macKey, content.getSerialized());

    return new UnidentifiedSenderMessage(ephemeral.getPublicKey(), staticKeyCiphertext, messageBytes).getSerialized();
  }

  public DecryptionResult decrypt(byte[] ciphertext)
          throws
          InvalidMetadataMessageException, InvalidMetadataVersionException,
          ProtocolInvalidMessageException, ProtocolInvalidKeyException,
          ProtocolNoSessionException, ProtocolLegacyMessageException,
          ProtocolInvalidVersionException, ProtocolDuplicateMessageException,
          ProtocolInvalidKeyIdException, SelfSendException {
    UnidentifiedSenderMessageContent content;

    try {
      ECKeyPair ourIdentity = signalProtocolStore.getIdentityKeyPair();
      UnidentifiedSenderMessage wrapper = new UnidentifiedSenderMessage(ciphertext);
      byte[] ephemeralSalt = ByteUtil.combine("UnidentifiedDelivery".getBytes(), ourIdentity.getPublicKey().getBytes(), wrapper.getEphemeral().getBytes());
      EphemeralKeys ephemeralKeys = calculateEphemeralKeys(wrapper.getEphemeral(), ourIdentity.getPrivateKey(), ephemeralSalt);
      byte[] staticKeyBytes = decrypt(ephemeralKeys.cipherKey, ephemeralKeys.macKey, wrapper.getEncryptedStatic());

      ECPublicKey staticKey = new ECPublicKey(staticKeyBytes);
      byte[] staticSalt = ByteUtil.combine(ephemeralKeys.chainKey, wrapper.getEncryptedStatic());
      StaticKeys staticKeys = calculateStaticKeys(staticKey, ourIdentity.getPrivateKey(), staticSalt);
      byte[] messageBytes = decrypt(staticKeys.cipherKey, staticKeys.macKey, wrapper.getEncryptedMessage());

      content = new UnidentifiedSenderMessageContent(messageBytes);
      if (Arrays.equals(ourIdentity.getPublicKey().getBytes(), content.getSenderIdentityKey())) {
        throw new SelfSendException();
      }
    } catch (InvalidKeyException | InvalidMacException e) {
      throw new InvalidMetadataMessageException(e);
    }

    try {
      return new DecryptionResult(content.getSenderAddress(), decrypt(content));
    } catch (InvalidMessageException e) {
      throw new ProtocolInvalidMessageException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    } catch (InvalidKeyException e) {
      throw new ProtocolInvalidKeyException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    } catch (NoSessionException e) {
      throw new ProtocolNoSessionException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    } catch (LegacyMessageException e) {
      throw new ProtocolLegacyMessageException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    } catch (InvalidVersionException e) {
      throw new ProtocolInvalidVersionException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    } catch (DuplicateMessageException e) {
      throw new ProtocolDuplicateMessageException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    } catch (InvalidKeyIdException e) {
      throw new ProtocolInvalidKeyIdException(e, content.getSenderIdentityKey(), content.getSenderDeviceId());
    }
  }

  public int getSessionVersion(SignalProtocolAddress remoteAddress) {
    return new SessionCipher(signalProtocolStore, remoteAddress).getSessionVersion();
  }

  private EphemeralKeys calculateEphemeralKeys(ECPublicKey ephemeralPublic, ECPrivateKey ephemeralPrivate, byte[] salt) throws InvalidKeyException {
    try {
      byte[] ephemeralSecret = Curve.calculateAgreement(ephemeralPublic, ephemeralPrivate);
      byte[] ephemeralDerived = new HKDFv3().deriveSecrets(ephemeralSecret, salt, new byte[0], 96);
      byte[][] ephemeralDerivedParts = ByteUtil.split(ephemeralDerived, 32, 32, 32);

      return new EphemeralKeys(ephemeralDerivedParts[0], ephemeralDerivedParts[1], ephemeralDerivedParts[2]);
    } catch (ParseException e) {
      throw new AssertionError(e);
    }
  }

  private StaticKeys calculateStaticKeys(ECPublicKey staticPublic, ECPrivateKey staticPrivate, byte[] salt) throws InvalidKeyException {
    try {
      byte[] staticSecret = Curve.calculateAgreement(staticPublic, staticPrivate);
      byte[] staticDerived = new HKDFv3().deriveSecrets(staticSecret, salt, new byte[0], 96);
      byte[][] staticDerivedParts = ByteUtil.split(staticDerived, 32, 32, 32);

      return new StaticKeys(staticDerivedParts[1], staticDerivedParts[2]);
    } catch (ParseException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] decrypt(UnidentifiedSenderMessageContent message)
          throws InvalidVersionException, InvalidMessageException, InvalidKeyException, DuplicateMessageException, InvalidKeyIdException, LegacyMessageException, NoSessionException {
    SignalProtocolAddress sender = message.getSenderAddress();

    switch (message.getType()) {
      case CiphertextMessage.WHISPER_TYPE:
        return new SessionCipher(signalProtocolStore, sender).decrypt(new SignalMessage(message.getContent()));
      case CiphertextMessage.PREKEY_TYPE: {
        PreKeySignalMessage signalMessage = new PreKeySignalMessage(message.getContent());
        return new SessionCipher(signalProtocolStore, sender).decrypt(signalMessage);
      }
      default:
        throw new InvalidMessageException("Unknown type: " + message.getType());
    }
  }

  private byte[] encrypt(SecretKeySpec cipherKey, SecretKeySpec macKey, byte[] plaintext) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, cipherKey, new IvParameterSpec(new byte[16]));

      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(macKey);

      byte[] ciphertext = cipher.doFinal(plaintext);
      byte[] ourFullMac = mac.doFinal(ciphertext);
      byte[] ourMac = ByteUtil.trim(ourFullMac, 10);

      return ByteUtil.combine(ciphertext, ourMac);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] decrypt(SecretKeySpec cipherKey, SecretKeySpec macKey, byte[] ciphertext) throws InvalidMacException {
    try {
      if (ciphertext.length < 10) {
        throw new InvalidMacException("Ciphertext not long enough for MAC!");
      }

      byte[][] ciphertextParts = ByteUtil.split(ciphertext, ciphertext.length - 10, 10);

      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(macKey);

      byte[] digest = mac.doFinal(ciphertextParts[0]);
      byte[] ourMac = ByteUtil.trim(digest, 10);
      byte[] theirMac = ciphertextParts[1];

      if (!MessageDigest.isEqual(ourMac, theirMac)) {
        throw new InvalidMacException("Bad mac!");
      }

      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(new byte[16]));

      return cipher.doFinal(ciphertextParts[0]);
    } catch (NoSuchAlgorithmException | java.security.InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      throw new AssertionError(e);
    }
  }

  public static class DecryptionResult {
    private final SignalProtocolAddress senderAddress;
    private final byte[] paddedMessage;

    private DecryptionResult(SignalProtocolAddress senderAddress, byte[] paddedMessage) {
      this.senderAddress = senderAddress;
      this.paddedMessage = paddedMessage;
    }

    public SignalProtocolAddress getSenderAddress() {
      return senderAddress;
    }

    public byte[] getPaddedMessage() {
      return paddedMessage;
    }
  }

  private static class EphemeralKeys {
    private final byte[] chainKey;
    private final SecretKeySpec cipherKey;
    private final SecretKeySpec macKey;

    private EphemeralKeys(byte[] chainKey, byte[] cipherKey, byte[] macKey) {
      this.chainKey = chainKey;
      this.cipherKey = new SecretKeySpec(cipherKey, "AES");
      this.macKey = new SecretKeySpec(macKey, "HmacSHA256");
    }
  }

  private static class StaticKeys {
    private final SecretKeySpec cipherKey;
    private final SecretKeySpec macKey;

    private StaticKeys(byte[] cipherKey, byte[] macKey) {
      this.cipherKey = new SecretKeySpec(cipherKey, "AES");
      this.macKey = new SecretKeySpec(macKey, "HmacSHA256");
    }
  }
}