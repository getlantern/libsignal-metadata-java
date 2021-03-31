package org.signal.libsignal.metadata;

import junit.framework.TestCase;

import org.signal.libsignal.metadata.SealedSessionCipher.DecryptionResult;
import org.whispersystems.libsignal.DeviceId;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import javax.crypto.spec.SecretKeySpec;

public class SealedSessionCipherTest extends TestCase {
  private static final DeviceId staticDeviceId = DeviceId.random();

  public void testEncryptDecryptSuccessAndSpoofingFailure() throws Exception {
    // bob is this test's main recipient of messages. Everyone else has his pre-keys and will send him session initiation messages to start
    TestInMemorySignalProtocolStore bobStore           = new TestInMemorySignalProtocolStore();
    // alice is a trusted contact with whom Bob will successfully exchange messages
    TestInMemorySignalProtocolStore aliceStore         = new TestInMemorySignalProtocolStore();
    // sally is a trusted contact that will never successfully exchange messages with bob and will always be sending session initiation messages to him
    TestInMemorySignalProtocolStore sallyStore         = new TestInMemorySignalProtocolStore();
    // trustedBadGuy is someone trusted by bob but who ends up trying to spoof the sender on messages that actually came from alice and sally
    TestInMemorySignalProtocolStore trustedBadGuyStore = new TestInMemorySignalProtocolStore();
    // unknownBadGuy is someone unknown to bob who tries to spoof the sender on messages that actually came from alice and sally
    TestInMemorySignalProtocolStore unknownBadGuyStore = new TestInMemorySignalProtocolStore();

    SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobStore.getIdentityKeyPair().getPublicKey(), staticDeviceId);
    SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceStore.getIdentityKeyPair().getPublicKey(), staticDeviceId);
    SignalProtocolAddress trustedBadGuyAddress = new SignalProtocolAddress(trustedBadGuyStore.getIdentityKeyPair().getPublicKey(), staticDeviceId);

    initializeSessions(bobStore, aliceStore, sallyStore, trustedBadGuyStore);

    SealedSessionCipher bobCipher           = new SealedSessionCipher(bobStore, staticDeviceId);
    SealedSessionCipher aliceCipher         = new SealedSessionCipher(aliceStore, staticDeviceId);
    SealedSessionCipher sallyCipher         = new SealedSessionCipher(sallyStore, staticDeviceId);
    SealedSessionCipher trustedBadGuyCipher = new SealedSessionCipher(trustedBadGuyStore, staticDeviceId);

    // first successfully do a bidirectional message exchange with alice, no sender spoofing
    // after this point, bob and alice have a successfully negotiated messaging session
    bidirectionalMessageExchange(aliceAddress, aliceCipher, bobAddress, bobCipher);

    /***********************************************************************************************
     * The below test checks various forms of sender address spoofing, all of which should fail.
     *
     * There are two layers of protection against spoofing:
     *
     *  1. All messages (session initiation messages and in-flight messages) include a MAC, which
     *     the sender calculates using their own key and the intended recipient's key (along with
     *     the message contents). Upon attempting to decrypt that message using the spoofed sender
     *     identity, the Mac check fails.
     *     See {@link org.whispersystems.libsignal.protocol.SignalMessage#getMac(ECPublicKey, ECPublicKey, SecretKeySpec, byte[])}
     *
     *  2. For regular (non initiation) messages, if the spoofer is unknown to the recipient or the
     *     recipient has never sent the spoofer a message, thereby establishing a session, then we
     *     don't even get to the MAC check because we can't even find an active session in the local
     *     session store that corresponds to the spoofed sender.
     *
     **********************************************************************************************/
    String plainText = "Spoofer unknown to Bob, message is a session initiation message (PreKeySignalMessage)";
    byte[] spoofedCiphertext = sallyCipher.encrypt(unknownBadGuyStore.getIdentityKeyPair(), bobAddress, plainText.getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed on: " + plainText);
    } catch (ProtocolInvalidMessageException e) {
      assertEquals("Bad Mac!", getRootCause(e).getMessage());
    }

    plainText = "Spoofer is unknown to Bob, message is part of an existing session (SignalMessage)";
    spoofedCiphertext = aliceCipher.encrypt(unknownBadGuyStore.getIdentityKeyPair(), bobAddress, plainText.getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed on: " + plainText);
    } catch (ProtocolNoSessionException e) {
      assertTrue(getRootCause(e).getMessage().startsWith("No session for:"));
    }

    plainText = "Spoofer is known to Bob but has not yet successfully messaged with him, message is a session initiation message (PreKeySignalMessage)";
    spoofedCiphertext = sallyCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, plainText.getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed on: " + plainText);
    } catch (ProtocolInvalidMessageException e) {
      assertEquals("Bad Mac!", getRootCause(e).getMessage());
    }

    plainText = "Spoofer is known to Bob but has not yet successfully messaged with him, message is part of an existing session (SignalMessage)";
    spoofedCiphertext = aliceCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, plainText.getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed on: " + plainText);
    } catch (ProtocolNoSessionException e) {
      assertTrue(getRootCause(e).getMessage().startsWith("No session for:"));
    }

    // exchange messages to establish a trusted session between bob and trustedBadGuy
    bidirectionalMessageExchange(trustedBadGuyAddress, trustedBadGuyCipher, bobAddress, bobCipher);

    plainText = "Spoofer is known to Bob and has successfully messaged with him, message is a session initiation message (PreKeySignalMessage)";
    spoofedCiphertext = sallyCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, plainText.getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed on: " + plainText);
    } catch (ProtocolInvalidMessageException e) {
      assertEquals("Bad Mac!", getRootCause(e).getMessage());
    }

    plainText = "Spoofer is known to Bob and has successfully messaged with him, message is part of an existing session (SignalMessage)";
    spoofedCiphertext = aliceCipher.encrypt(trustedBadGuyStore.getIdentityKeyPair(), bobAddress, plainText.getBytes());
    try {
      bobCipher.decrypt(spoofedCiphertext);
      fail("should have failed on: " + plainText);
    } catch (ProtocolInvalidMessageException e) {
      assertEquals("Bad Mac!", getRootCause(e).getMessage());
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

  private void initializeSessions(TestInMemorySignalProtocolStore recipientStore, TestInMemorySignalProtocolStore ...senderStores)
      throws InvalidKeyException
  {
    int recipientSignedPreKeyId              = 2;
    int recipientPreKeyId                    = 1;
    ECKeyPair          recipientIdentityKey  = recipientStore.getIdentityKeyPair();
    SignedPreKeyRecord recipientSignedPreKey = KeyHelper.generateSignedPreKey(recipientIdentityKey, recipientPreKeyId);
    recipientStore.storeSignedPreKey(recipientSignedPreKeyId, recipientSignedPreKey);

    for (TestInMemorySignalProtocolStore senderStore : senderStores) {
      ECKeyPair          recipientPreKey       = Curve.generateKeyPair();
      recipientStore.storePreKey(recipientPreKeyId, new PreKeyRecord(recipientPreKeyId, recipientPreKey));
      PreKeyBundle bobBundle             = new PreKeyBundle(recipientPreKeyId, recipientPreKey.getPublicKey(), recipientSignedPreKeyId, recipientSignedPreKey.getKeyPair().getPublicKey(), recipientSignedPreKey.getSignature(), recipientIdentityKey.getPublicKey());
      SessionBuilder aliceSessionBuilder = new SessionBuilder(senderStore, new SignalProtocolAddress(recipientStore.getIdentityKeyPair().getPublicKey(), staticDeviceId));
      aliceSessionBuilder.process(bobBundle);
      recipientPreKeyId++;
    }
  }

  private Throwable getRootCause(Throwable t) {
    Throwable cause = t;
    while (cause != null) {
      if (cause.getCause() == null) {
        break;
      }
      cause = cause.getCause();
    }
    return cause;
  }
}
