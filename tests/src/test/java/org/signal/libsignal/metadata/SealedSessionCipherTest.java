package org.signal.libsignal.metadata;

import junit.framework.TestCase;

import org.signal.libsignal.metadata.SealedSessionCipher.DecryptionResult;
import org.signal.libsignal.metadata.encoding.UserId;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

public class SealedSessionCipherTest extends TestCase {
  private static final int staticDeviceId = 1;

  public void testEncryptDecryptSuccess() throws Exception {
    TestInMemorySignalProtocolStore aliceStore         = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore           = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore trustedBadGuyStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore unknownBadGuyStore = new TestInMemorySignalProtocolStore();

    String aliceUserId = UserId.encodeToString(aliceStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceUserId, staticDeviceId);
    String bobUserId = UserId.encodeToString(bobStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobUserId, staticDeviceId);
    String trustedBadGuyUserID = UserId.encodeToString(trustedBadGuyStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress trustedBadGuyAddress = new SignalProtocolAddress(trustedBadGuyUserID, staticDeviceId);
    String unknownBadGuyUserID = UserId.encodeToString(unknownBadGuyStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress unknownBadGuyAddress = new SignalProtocolAddress(unknownBadGuyUserID, staticDeviceId);

    initializeSessions(bobStore, aliceStore, trustedBadGuyStore);

    SealedSessionCipher aliceCipher         = new SealedSessionCipher(aliceStore, staticDeviceId);
    SealedSessionCipher bobCipher           = new SealedSessionCipher(bobStore, staticDeviceId);
    SealedSessionCipher trustedBadGuyCipher = new SealedSessionCipher(trustedBadGuyStore, staticDeviceId);
    SealedSessionCipher unknownBadGuyCipher = new SealedSessionCipher(trustedBadGuyStore, staticDeviceId);

    bidirectionalMessageExchange(aliceAddress, aliceCipher, bobAddress, bobCipher);

    /***********************************************************************************************
     * The below test conditions test various forms of sender address spoofing, all of which should
     * fail.
     *
     * 1. Someone unknown to Bob attempts to make it look like the message came from them (unknownBadGuy)
     * 2. Someone known to Bob who hasn't yet successfully initiated a messaging session (trustedBadGuy)
     * 3. Someone known to Bob who has successfully initiated a messaging session (trustedBadGuy)
     **********************************************************************************************/
    byte[] spoofedCiphertext = aliceCipher.encrypt(unknownBadGuyStore.getIdentityKeyPair(), bobAddress, "Someone unknown to Bob is spoofing Alice!".getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed to decrypt with unknown spoofed sender on regular encrypted message");
    } catch (ProtocolNoSessionException e) {
      // okay
    }

    spoofedCiphertext = aliceCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, "Someone known to Bob who has not yet communicated with him is spoofing Alice!".getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed to decrypt with trusted (but as yet not communicated) spoofed sender on regular encrypted message");
    } catch (ProtocolNoSessionException e) {
      // okay
    }

    bidirectionalMessageExchange(trustedBadGuyAddress, trustedBadGuyCipher, bobAddress, bobCipher);
    spoofedCiphertext = aliceCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, "Someone known to Bob who has previously communicated with him is spoofing Alice!".getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed to decrypt with trusted and previously communicated spoofed sender on regular encrypted message");
    } catch (ProtocolInvalidMessageException e) {
      // okay
    }
  }

  private void bidirectionalMessageExchange(SignalProtocolAddress senderAddress,
                                            SealedSessionCipher senderCipher,
                                            SignalProtocolAddress recipientAddress,
                                            SealedSessionCipher recipientCipher) throws Exception {
    byte[] ciphertext = senderCipher.encrypt(recipientAddress, "ping".getBytes());
    DecryptionResult plaintext = recipientCipher.decrypt(ciphertext);
    assertEquals(new String(plaintext.getPaddedMessage()), "ping");
    assertEquals(plaintext.getSenderAddress(), senderAddress);

    byte[] responseCiphertext = recipientCipher.encrypt(senderAddress, "pong".getBytes());
    DecryptionResult responsePlaintext = senderCipher.decrypt(responseCiphertext);
    assertEquals(new String(responsePlaintext.getPaddedMessage()), "pong");
  }



  /**
   * This test simulates what would happen if an intermediary intercepts a session initiation message
   * wrapped in a sealed sender message and replaces the sender with a different address. This should
   * fail because the IdentityKey on the session initiation message doesn't match the spoofed sender
   * address.
   *
   * @throws Exception
   */
  public void testSenderSpoofingFailsOnSessionInitiation() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore trustedBadGuyStore   = new TestInMemorySignalProtocolStore();

    String trustedBadGuyUserId = UserId.encodeToString(trustedBadGuyStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress trustedBadGuyAddress = new SignalProtocolAddress(trustedBadGuyUserId, staticDeviceId);
    String bobUserId = UserId.encodeToString(bobStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobUserId, staticDeviceId);

    initializeSessions(bobStore, aliceStore);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, staticDeviceId);
    byte[] ciphertext = aliceCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, "smert za smert".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, staticDeviceId);
    try {
      DecryptionResult plaintext = bobCipher.decrypt(ciphertext);
      fail("should have failed to decrypt with spoofed sender on session initiation message");
    } catch (Exception e) {
      // "bad guy's identity should not be in Bob's store after failure to decrypt"
      assertNull(bobStore.getIdentity(trustedBadGuyAddress));
    }
  }

  private void initializeSessions(TestInMemorySignalProtocolStore recipientStore, TestInMemorySignalProtocolStore ...senderStores)
      throws InvalidKeyException, UntrustedIdentityException
  {
    int recipientRegistrationId              = 1;
    int recipientSignedPreKeyId              = 2;
    int recipientPreKeyId                    = 1;
    IdentityKeyPair    recipientIdentityKey  = recipientStore.getIdentityKeyPair();
    SignedPreKeyRecord recipientSignedPreKey = KeyHelper.generateSignedPreKey(recipientIdentityKey, recipientPreKeyId);
    String recipientId = UserId.encodeToString(recipientStore.getIdentityKeyPair().getPublicKey().serialize());
    recipientStore.storeSignedPreKey(recipientSignedPreKeyId, recipientSignedPreKey);

    for (TestInMemorySignalProtocolStore senderStore : senderStores) {
      ECKeyPair          recipientPreKey       = Curve.generateKeyPair();
      recipientStore.storePreKey(recipientPreKeyId, new PreKeyRecord(recipientPreKeyId, recipientPreKey));
      PreKeyBundle bobBundle             = new PreKeyBundle(recipientRegistrationId, staticDeviceId, recipientPreKeyId, recipientPreKey.getPublicKey(), recipientSignedPreKeyId, recipientSignedPreKey.getKeyPair().getPublicKey(), recipientSignedPreKey.getSignature(), recipientIdentityKey.getPublicKey());
      SessionBuilder aliceSessionBuilder = new SessionBuilder(senderStore, new SignalProtocolAddress(recipientId, staticDeviceId));
      aliceSessionBuilder.process(bobBundle);
      recipientPreKeyId++;
    }
  }
}
