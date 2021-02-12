package org.signal.libsignal.metadata.signedaddress;


import junit.framework.TestCase;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class SignedAddressTest extends TestCase {

  public void testGoodSignature() throws InvalidAddressException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] userId = key.getPublicKey().serialize();
    int deviceId = 1;
    SignedAddress address = new SignedAddress(userId, deviceId, key.getPrivateKey());
    byte[] serialized = address.getSerialized();
    SignedAddress roundTripped = new SignedAddress(serialized);
    assertEquals(address.getSenderAddress(), roundTripped.getSenderAddress());
  }

  public void testBadSignature() throws InvalidAddressException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] userId = key.getPublicKey().serialize();
    int deviceId = 1;
    SignedAddress address = new SignedAddress(userId, deviceId, key.getPrivateKey());

    // serialize and mess with signature
    byte[] serialized = address.getSerialized();
    serialized[40] += 1;
    try {
      SignedAddress roundTripped = new SignedAddress(serialized);
      fail("deserializing address with invalid signature should have failed");
    } catch (InvalidAddressException e) {
      // expected
    }
  }

  public void testBadUserId() throws InvalidAddressException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] userId = key.getPublicKey().serialize();
    int deviceId = 1;
    SignedAddress address = new SignedAddress(userId, deviceId, key.getPrivateKey());

    // serialize and mess with userId (public key)
    byte[] serialized = address.getSerialized();
    serialized[92] += 1;
    try {
      SignedAddress roundTripped = new SignedAddress(serialized);
      fail("deserializing address with invalid userId should have failed");
    } catch (InvalidAddressException e) {
      // expected
    }
  }
}