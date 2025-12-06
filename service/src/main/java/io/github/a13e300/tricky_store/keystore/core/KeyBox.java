/*
 * Copyright (C) 2024 TrickyStore
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.a13e300.tricky_store.keystore.core;

import org.bouncycastle.openssl.PEMKeyPair;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Represents a hardware-backed key with its certificate chain.
 * This is the fundamental unit for key attestation simulation.
 * 
 * KeyBox holds:
 * - The private key (in PEM and Java KeyPair forms)
 * - The certificate chain signed by Google's attestation root
 * 
 * @see <a href="https://source.android.com/docs/security/features/keystore/attestation">Key Attestation</a>
 */
public final class KeyBox {
    
    private final PEMKeyPair pemKeyPair;
    private final KeyPair keyPair;
    private final List<Certificate> certificateChain;
    private final String algorithm;
    
    /**
     * Creates a new KeyBox.
     *
     * @param pemKeyPair The PEM-encoded key pair for serialization
     * @param keyPair The Java security KeyPair for cryptographic operations
     * @param certificateChain The certificate chain, with the leaf certificate first
     * @param algorithm The key algorithm (EC or RSA)
     */
    public KeyBox(PEMKeyPair pemKeyPair, KeyPair keyPair, 
                  List<Certificate> certificateChain, String algorithm) {
        this.pemKeyPair = pemKeyPair;
        this.keyPair = keyPair;
        this.certificateChain = Collections.unmodifiableList(certificateChain);
        this.algorithm = algorithm;
    }
    
    /**
     * @return The PEM-encoded key pair
     */
    public PEMKeyPair getPemKeyPair() {
        return pemKeyPair;
    }
    
    /**
     * @return The Java security KeyPair
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }
    
    /**
     * @return The unmodifiable certificate chain
     */
    public List<Certificate> getCertificateChain() {
        return certificateChain;
    }
    
    /**
     * @return The key algorithm (EC or RSA)
     */
    public String getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Gets the issuer certificate (first in chain).
     * @return The issuer certificate used for signing leaf certificates
     */
    public Certificate getIssuerCertificate() {
        return certificateChain.isEmpty() ? null : certificateChain.get(0);
    }
}
