package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;

public class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
  public TestInMemorySignalProtocolStore() {
    super(generateIdentityKeyPair());
  }

  private static ECKeyPair generateIdentityKeyPair() {
    return Curve.generateKeyPair();
  }
}