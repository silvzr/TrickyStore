package io.github.a13e300.tricky_store.keystore;

import android.content.pm.PackageManager;
import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.Tag;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.util.Pair;

import androidx.annotation.Nullable;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import io.github.a13e300.tricky_store.KeyCache;
import io.github.a13e300.tricky_store.Config;
import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.TrickyStoreUtils;
import top.qwq2333.ohmykeymint.IOhMyKsService;

public final class CertHack {
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
    private static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
    private static final Map<String, KeyBox> keyboxes = new HashMap<>();
    private static final Map<Key, String> leafAlgorithm = new HashMap<>();
    private static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;

    private static final CertificateFactory certificateFactory;

    public record Key(String alias, int uid) {
    }

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (Throwable t) {
            Logger.e("", t);
            throw new RuntimeException(t);
        }
    }

    private static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;

    public static boolean canHack() {
        return !keyboxes.isEmpty();
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(TrickyStoreUtils.trimLine(key)))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(TrickyStoreUtils.trimLine(cert)))) {
            return certificateFactory.generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }

    private static byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString derOctectString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        return derOctectString.getOctets();
    }

    public static void readFromXml(String data, IOhMyKsService omk) {
        keyboxes.clear();
        if (data == null) {
            Logger.i("clear all keyboxes");
            return;
        }
        XMLParser xmlParser = new XMLParser(data);

        try {
            int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                    "AndroidAttestation.NumberOfKeyboxes").get("text")));
            for (int i = 0; i < numberOfKeyboxes; i++) {
                String keyboxAlgorithm = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                String privateKey = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates").get("text")));

                LinkedList<Certificate> certificateChain = new LinkedList<>();

                for (int j = 0; j < numberOfCertificates; j++) {
                    Map<String, String> certData = xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                    certificateChain.add(parseCert(certData.get("text")));
                }
                String algo;
                if (keyboxAlgorithm.equalsIgnoreCase("ecdsa")) {
                    algo = KeyProperties.KEY_ALGORITHM_EC;
                } else {
                    algo = KeyProperties.KEY_ALGORITHM_RSA;
                }
                var pemKp = parseKeyPair(privateKey);
                var kp = new JcaPEMKeyConverter().getKeyPair(pemKp);
                keyboxes.put(algo, new KeyBox(pemKp, kp, certificateChain));

                if (omk != null) {
                    try {
                        if (keyboxAlgorithm.equalsIgnoreCase("ecdsa")) {
                            ArrayList<android.hardware.security.keymint.Certificate> list = new ArrayList<>();

                            for (int j = 0; j < numberOfCertificates; j++) {
                                Map<String, String> certData = xmlParser.obtainPath(
                                        "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                                var cert = new android.hardware.security.keymint.Certificate();
                                cert.encodedCertificate = Base64.getDecoder().decode(TrickyStoreUtils.parsePemToBase64(certData.get("text")));
                                list.add(cert);
                            }

                            omk.updateEcKeybox(Base64.getDecoder().decode(TrickyStoreUtils.parsePemToBase64(privateKey)), list);
                        } else if (keyboxAlgorithm.equalsIgnoreCase("rsa")) {
                            ArrayList<android.hardware.security.keymint.Certificate> list = new ArrayList<>();
                            for (int j = 0; j < numberOfCertificates; j++) {
                                Map<String, String> certData = xmlParser.obtainPath(
                                        "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                                var cert = new android.hardware.security.keymint.Certificate();
                                cert.encodedCertificate = Base64.getDecoder().decode(TrickyStoreUtils.parsePemToBase64(certData.get("text")));
                                list.add(cert);
                            }

                            omk.updateRsaKeybox(Base64.getDecoder().decode(TrickyStoreUtils.parsePemToBase64(privateKey)), list);
                        }
                    } catch (Exception e) {
                        Logger.e("Unable to update keybox to OMK", e);
                    }
                }
            }
            Logger.i("update " + numberOfKeyboxes + " keyboxes");
        } catch (Throwable t) {
            Logger.e("Error loading xml file (keyboxes cleared): " + t);
        }
    }

    public static Certificate[] hackCertificateChain(Certificate[] caList) {
        if (caList == null) throw new UnsupportedOperationException("caList is null!");
        try {
            X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(caList[0].getEncoded()));
            byte[] bytes = leaf.getExtensionValue(OID.getId());
            if (bytes == null) return caList;

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension ext = leafHolder.getExtension(OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];
            ASN1EncodableVector vector = new ASN1EncodableVector();
            ASN1Encodable rootOfTrust = null;

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) {
                    rootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                    continue;
                }
                vector.add(taggedObject);
            }

            LinkedList<Certificate> certificates;
            X509v3CertificateBuilder builder;
            ContentSigner signer;

            var k = keyboxes.get(leaf.getPublicKey().getAlgorithm());
            if (k == null)
                throw new UnsupportedOperationException("unsupported algorithm " + leaf.getPublicKey().getAlgorithm());
            certificates = new LinkedList<>(k.certificates);
            builder = new X509v3CertificateBuilder(
                    new X509CertificateHolder(
                            certificates.get(0).getEncoded()
                    ).getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo()
            );
            signer = new JcaContentSignerBuilder(leaf.getSigAlgName())
                    .build(k.keyPair.getPrivate());

            byte[] verifiedBootKey = TrickyStoreUtils.getBootKey();
            byte[] verifiedBootHash = null;
            try {
                if (!(rootOfTrust instanceof ASN1Sequence r)) {
                    throw new CertificateParsingException("Expected sequence for root of trust, found "
                            + rootOfTrust.getClass().getName());
                }
                verifiedBootHash = getByteArrayFromAsn1(r.getObjectAt(3));
            } catch (Throwable t) {
                Logger.e("failed to get verified boot key or hash from original, use randomly generated instead", t);
            }

            if (verifiedBootHash == null) {
                verifiedBootHash = TrickyStoreUtils.getBootHash();
            }

            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };

            ASN1Sequence hackedRootOfTrust = new DERSequence(rootOfTrustEnc);
            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, hackedRootOfTrust);
            vector.add(rootOfTrustTagObj);

            // Sort by tag number for DER compliance
            List<ASN1TaggedObject> sortedTags = new ArrayList<>();
            for (int i = 0; i < vector.size(); i++) {
                sortedTags.add((ASN1TaggedObject) vector.get(i));
            }
            sortedTags.sort(Comparator.comparingInt(ASN1TaggedObject::getTagNo));
            ASN1EncodableVector sortedVector = new ASN1EncodableVector();
            for (ASN1TaggedObject tag : sortedTags) {
                sortedVector.add(tag);
            }

            ASN1Sequence hackEnforced = new DERSequence(sortedVector);
            encodables[7] = hackEnforced;
            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : leafHolder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(leafHolder.getExtension(extensionOID));
            }
            certificates.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));

            return certificates.toArray(new Certificate[0]);

        } catch (Throwable t) {
            Logger.e("", t);
        }
        return caList;
    }

    public static byte[] hackCertificateChainCA(byte[] caList, String alias, int uid) {
        if (caList == null) throw new UnsupportedOperationException("caList is null!");
        try {
            var key = new Key(alias, uid);
            var algorithm = leafAlgorithm.get(key);
            leafAlgorithm.remove(key);
            var k = keyboxes.get(algorithm);
            if (k == null)
                throw new UnsupportedOperationException("unsupported algorithm " + algorithm);
            return Utils.toBytes(k.certificates);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return caList;
    }

    public static byte[] hackCertificateChainUSR(byte[] certificate, String alias, int uid) {
        if (certificate == null) throw new UnsupportedOperationException("leaf is null!");
        try {
            X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate));
            byte[] bytes = leaf.getExtensionValue(OID.getId());
            if (bytes == null) return certificate;

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension ext = leafHolder.getExtension(OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];
            ASN1EncodableVector vector = new ASN1EncodableVector();
            ASN1Encodable rootOfTrust = null;

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) {
                    rootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                    continue;
                }
                vector.add(taggedObject);
            }

            LinkedList<Certificate> certificates;
            X509v3CertificateBuilder builder;
            ContentSigner signer;

            leafAlgorithm.put(new Key(alias, uid), leaf.getPublicKey().getAlgorithm());
            var k = keyboxes.get(leaf.getPublicKey().getAlgorithm());
            if (k == null)
                throw new UnsupportedOperationException("unsupported algorithm " + leaf.getPublicKey().getAlgorithm());
            certificates = new LinkedList<>(k.certificates);
            builder = new X509v3CertificateBuilder(
                    new X509CertificateHolder(
                            certificates.get(0).getEncoded()
                    ).getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo()
            );
            signer = new JcaContentSignerBuilder(leaf.getSigAlgName())
                    .build(k.keyPair.getPrivate());

            byte[] verifiedBootKey = TrickyStoreUtils.getBootKey();
            byte[] verifiedBootHash = null;
            try {
                if (!(rootOfTrust instanceof ASN1Sequence r)) {
                    throw new CertificateParsingException("Expected sequence for root of trust, found "
                            + rootOfTrust.getClass().getName());
                }
                verifiedBootHash = getByteArrayFromAsn1(r.getObjectAt(3));
            } catch (Throwable t) {
                Logger.e("failed to get verified boot key or hash from original, use randomly generated instead", t);
            }

            if (verifiedBootHash == null) {
                verifiedBootHash = TrickyStoreUtils.getBootHash();
            }

            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };

            ASN1Sequence hackedRootOfTrust = new DERSequence(rootOfTrustEnc);
            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, hackedRootOfTrust);
            vector.add(rootOfTrustTagObj);

            // Sort by tag number for DER compliance
            List<ASN1TaggedObject> sortedTags = new ArrayList<>();
            for (int i = 0; i < vector.size(); i++) {
                sortedTags.add((ASN1TaggedObject) vector.get(i));
            }
            sortedTags.sort(Comparator.comparingInt(ASN1TaggedObject::getTagNo));
            ASN1EncodableVector sortedVector = new ASN1EncodableVector();
            for (ASN1TaggedObject tag : sortedTags) {
                sortedVector.add(tag);
            }

            ASN1Sequence hackEnforced = new DERSequence(sortedVector);
            encodables[7] = hackEnforced;
            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : leafHolder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(leafHolder.getExtension(extensionOID));
            }
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer)).getEncoded();

        } catch (Throwable t) {
            Logger.e("", t);
        }
        return certificate;
    }

    public static KeyPair generateKeyPair(KeyGenParameters params) {
        KeyPair kp;
        try {
            var algo = params.algorithm;
            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + params.keySize);
                kp = buildECKeyPair(params);
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + params.keySize);
                kp = buildRSAKeyPair(params);
            } else {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }
            return kp;
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    public static List<byte[]> generateChain(int uid, KeyGenParameters params, KeyPair kp) {
        KeyPair rootKP;
        X500Name issuer;
        KeyBox keyBox = null;
        try {
            var algo = params.algorithm;
            if (algo == Algorithm.EC) {
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_EC);
            } else if (algo == Algorithm.RSA) {
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_RSA);
            }
            if (keyBox == null) {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }
            rootKP = keyBox.keyPair;
            issuer = new X509CertificateHolder(
                    keyBox.certificates.get(0).getEncoded()
            ).getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer,
                    new BigInteger("1"),//params.certificateSerial,
                    params.certificateNotBefore,
                    ((X509Certificate) keyBox.certificates.get(0)).getNotAfter(),//params.certificateNotAfter,
                    new X500Name("CN=Android KeyStore Key"),//params.certificateSubject,
                    kp.getPublic()
            );

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            certBuilder.addExtension(createExtension(params, uid));

            ContentSigner contentSigner;
            if (algo == Algorithm.EC) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootKP.getPrivate());
            }
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            var leaf = new JcaX509CertificateConverter().getCertificate(certHolder);
            List<Certificate> chain = new ArrayList<>(keyBox.certificates);
            chain.add(0, leaf);
            //Logger.d("Successfully generated X500 Cert for alias: " + descriptor.alias);
            return Utils.toListBytes(chain);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    public static Pair<KeyPair, List<Certificate>> generateKeyPair(int uid, KeyDescriptor descriptor, KeyDescriptor attestKeyDescriptor, KeyGenParameters params) {
        Logger.i("Requested KeyPair with alias: " + descriptor.alias);
        boolean attestPurpose = attestKeyDescriptor != null;
        if (attestPurpose)
            Logger.i("Requested KeyPair with attestKey: " + attestKeyDescriptor.alias);
        KeyPair rootKP;
        X500Name issuer;
        int size = params.keySize;
        KeyPair kp = null;
        KeyBox keyBox = null;
        try {
            var algo = params.algorithm;
            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + size);
                kp = buildECKeyPair(params);
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_EC);
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + size);
                kp = buildRSAKeyPair(params);
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_RSA);
            }
            if (keyBox == null) {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }
            rootKP = keyBox.keyPair;
            issuer = new X509CertificateHolder(
                    keyBox.certificates.get(0).getEncoded()
            ).getSubject();

            if (attestPurpose) {
                var info = KeyCache.getInstance().getKeyPairChain(uid, attestKeyDescriptor.alias);
                if (info != null) {
                    rootKP = info.keyPair();
                    issuer = new X509CertificateHolder(
                            info.chain().get(0).getEncoded()
                    ).getSubject();
                }
            }

            Logger.d("certificateSubject: " + params.certificateSubject);
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer,
                    params.certificateSerial,
                    params.certificateNotBefore,
                    params.certificateNotAfter,
                    params.certificateSubject,
                    kp.getPublic()
            );

            params.purpose.forEach((it) -> Logger.d("CertHack: Purpose: " + it));
            KeyUsage keyUsage;
            if (params.purpose.stream().anyMatch((it) -> it == 0 || it == 1)) {
                keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
            } else {
                keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            }
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            if (params.attestationChallenge != null) {
                Extension ext = createExtension(params, uid);
                if (ext != null) {
                    certBuilder.addExtension(ext);
                } else {
                    Logger.e("Failed to create attestation extension");
                    return null;
                }
            } else {
                Logger.d("No attestationChallenge provided, skipping attestation extension");
            }

            ContentSigner contentSigner;
            if (algo == Algorithm.EC) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootKP.getPrivate());
            }
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            var leaf = new JcaX509CertificateConverter().getCertificate(certHolder);
            List<Certificate> chain;
            if (!attestPurpose) {
                chain = new ArrayList<>(keyBox.certificates);
            } else {
                chain = new ArrayList<>();
            }
            chain.add(0, leaf);
            Logger.d("Successfully generated X500 Cert for alias: " + descriptor.alias);
            return new Pair<>(kp, chain);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    public interface ImportedKeyCallback {
        Pair<PrivateKey, Certificate> getCachedKeypair();
    }

    public static Pair<KeyPair, List<Certificate>> generateKeyPairWithImportedKey(KeyDescriptor descriptor, KeyGenParameters params, ImportedKeyCallback callback) {
        Logger.i("Requested Imported KeyPair with alias: " + descriptor.alias);
        KeyPair rootKP;
        X500Name issuer;
        int size = params.keySize;
        KeyPair kp = null;
        try {
            var algo = params.algorithm;
            var pair = callback.getCachedKeypair();
            var certificate = pair.second;
            var privatekey = pair.first;
            rootKP = new KeyPair(certificate.getPublicKey(), privatekey);
            issuer = new X509CertificateHolder(
                    certificate.getEncoded()
            ).getSubject();

            if (algo == Algorithm.EC) {
                if (size < 1) size = 256;
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + size);
                kp = buildECKeyPair(params);
            } else if (algo == Algorithm.RSA) {
                if (size < 1) size = 2048;
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + size);
                kp = buildRSAKeyPair(params);
            } else {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }


            Logger.d("certificateSubject: " + params.certificateSubject);
            if (params.certificateSubject == null)
                params.certificateSubject = X500Name.getInstance(new DERSequence());
            if (params.certificateNotAfter == null)
                params.certificateNotAfter = new Date();
            if (params.certificateNotBefore == null)
                params.certificateNotBefore = new Date(params.certificateNotAfter.getTime() + 27L * 365 * 24 * 3600 * 1000);
            if (params.certificateSerial == null)
                params.certificateSerial = new BigInteger(String.valueOf(new Random().nextLong()));

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer,
                    params.certificateSerial,
                    params.certificateNotBefore,
                    params.certificateNotAfter,
                    params.certificateSubject,
                    kp.getPublic()
            );

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

            ContentSigner contentSigner;
            if (algo == Algorithm.EC) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootKP.getPrivate());
            }
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            var leaf = new JcaX509CertificateConverter().getCertificate(certHolder);
            List<Certificate> chain;
            chain = new ArrayList<>();
            chain.add(0, leaf);
            Logger.d("Successfully generated X500 Cert for alias: " + descriptor.alias);
            return new Pair<>(kp, chain);
        } catch (Throwable t) {
            Logger.e("", t);
        }

        return null;
    }

    private static KeyPair buildECKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec spec = new ECGenParameterSpec(params.ecCurveName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static KeyPair buildRSAKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                params.keySize, params.rsaPublicExponent);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static ASN1Encodable[] fromIntList(List<Integer> list) {
        ASN1Encodable[] result = new ASN1Encodable[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = new ASN1Integer(list.get(i));
        }
        return result;
    }

    private static Extension createExtension(KeyGenParameters params, int uid) {
        try {
            byte[] key = TrickyStoreUtils.getBootKey();
            byte[] hash = TrickyStoreUtils.getBootHash();

            // RootOfTrust ::= SEQUENCE {
            //     verifiedBootKey            OCTET_STRING,
            //     deviceLocked               BOOLEAN,
            //     verifiedBootState          VerifiedBootState (ENUMERATED),
            //     verifiedBootHash           OCTET_STRING,
            // }
            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(key), ASN1Boolean.TRUE,
                    new ASN1Enumerated(0), new DEROctetString(hash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            Logger.dd("params.purpose: " + params.purpose);

            // Hardware-enforced tags list
            var teeEnforcedList = new ArrayList<ASN1TaggedObject>();
            
            // Purpose [1] - only add if not empty
            if (params.purpose != null && !params.purpose.isEmpty()) {
                teeEnforcedList.add(new DERTaggedObject(true, 1, new DERSet(fromIntList(params.purpose))));
            }
            
            // Algorithm [2]
            teeEnforcedList.add(new DERTaggedObject(true, 2, new ASN1Integer(params.algorithm)));
            
            // Key size [3]
            teeEnforcedList.add(new DERTaggedObject(true, 3, new ASN1Integer(params.keySize)));
            
            // Digest [5] - only add if not empty
            if (params.digest != null && !params.digest.isEmpty()) {
                teeEnforcedList.add(new DERTaggedObject(true, 5, new DERSet(fromIntList(params.digest))));
            }
            
            // EC Curve [10] - only for EC keys
            if (params.algorithm == android.hardware.security.keymint.Algorithm.EC) {
                teeEnforcedList.add(new DERTaggedObject(true, 10, new ASN1Integer(params.ecCurve)));
            }
            
            // RSA public exponent [200] - only for RSA keys
            if (params.algorithm == android.hardware.security.keymint.Algorithm.RSA && params.rsaPublicExponent != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 200, new ASN1Integer(params.rsaPublicExponent)));
            }
            
            // Rollback resistance [303] - optional
            if (params.rollbackResistance) {
                teeEnforcedList.add(new DERTaggedObject(true, 303, DERNull.INSTANCE));
            }
            
            // Early boot only [305] - optional
            if (params.earlyBootOnly) {
                teeEnforcedList.add(new DERTaggedObject(true, 305, DERNull.INSTANCE));
            }
            
            // No auth required [503] - default true
            if (params.noAuthRequired) {
                teeEnforcedList.add(new DERTaggedObject(true, 503, DERNull.INSTANCE));
            }
            
            // Origin [702]
            teeEnforcedList.add(new DERTaggedObject(true, 702, new ASN1Integer(0)));
            
            // Root of Trust [704]
            teeEnforcedList.add(new DERTaggedObject(true, 704, rootOfTrustSeq));
            
            // OS Version [705]
            teeEnforcedList.add(new DERTaggedObject(true, 705, new ASN1Integer(TrickyStoreUtils.getOsVersion())));
            
            // OS Patch Level [706]
            teeEnforcedList.add(new DERTaggedObject(true, 706, new ASN1Integer(TrickyStoreUtils.getPatchLevel())));
            
            // Vendor Patch Level [718]
            teeEnforcedList.add(new DERTaggedObject(true, 718, new ASN1Integer(TrickyStoreUtils.getPatchLevelLong())));
            
            // Boot Patch Level [719]
            teeEnforcedList.add(new DERTaggedObject(true, 719, new ASN1Integer(TrickyStoreUtils.getPatchLevelLong())));
            
            // Device unique attestation [720] - optional
            if (params.deviceUniqueAttestation) {
                teeEnforcedList.add(new DERTaggedObject(true, 720, DERNull.INSTANCE));
            }
            
            // Module Hash [724] - KeyMint 4.0+
            byte[] moduleHash = TrickyStoreUtils.getModuleHash();
            if (moduleHash != null) {
                teeEnforcedList.add(new DERTaggedObject(true, 724, new DEROctetString(moduleHash)));
            }

            // Support device properties attestation (ID attestation tags)
            if (params.brand != null) {
                teeEnforcedList.addAll(TrickyStoreUtils.getTelephonyInfos());
            }

            // Sort TEE enforced by tag number (DER requirement)
            teeEnforcedList.sort(Comparator.comparingInt(ASN1TaggedObject::getTagNo));

            // Software-enforced tags list
            var swEnforcedList = new ArrayList<ASN1TaggedObject>();
            
            // Creation DateTime [701]
            swEnforcedList.add(new DERTaggedObject(true, 701, new ASN1Integer(System.currentTimeMillis())));
            
            // Attestation Application ID [709]
            ASN1OctetString applicationId;
            if (params.attestationApplicationId != null) {
                applicationId = new DEROctetString(params.attestationApplicationId);
            } else {
                applicationId = createApplicationId(uid);
            }
            swEnforcedList.add(new DERTaggedObject(true, 709, applicationId));
            
            // Sort software enforced by tag number (DER requirement)
            swEnforcedList.sort(Comparator.comparingInt(ASN1TaggedObject::getTagNo));

            ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(
                    teeEnforcedList.toArray(new ASN1Encodable[0]), 
                    swEnforcedList.toArray(new ASN1Encodable[0]), 
                    params);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    private static ASN1OctetString getAsn1OctetString(ASN1Encodable[] teeEnforcedEncodables, ASN1Encodable[] softwareEnforcedEncodables, KeyGenParameters params) throws IOException {
        ASN1Integer attestationVersion = new ASN1Integer(400);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
        ASN1Integer keymasterVersion = new ASN1Integer(400);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
        ASN1OctetString attestationChallenge = new DEROctetString(Objects.requireNonNullElseGet(params.attestationChallenge, () -> new byte[]{}));
        ASN1OctetString uniqueId = new DEROctetString("".getBytes());
        ASN1Encodable softwareEnforced = new DERSequence(softwareEnforcedEncodables);
        ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

        ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion,
                keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

        ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

        return new DEROctetString(keyDescriptionHackSeq);
    }

    private static DEROctetString createApplicationId(int uid) throws Throwable {
        var pm = Config.getInstance().getPackageManager();
        if (pm == null) {
            throw new IllegalStateException("createApplicationId: pm not found!");
        }
        var packages = pm.getPackagesForUid(uid);
        var size = packages.length;
        ASN1Encodable[] packageInfoAA = new ASN1Encodable[size];
        Set<Digest> signatures = new HashSet<>();
        var dg = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < size; i++) {
            var name = packages[i];
            var info = TrickyStoreUtils.getPackageInfoCompat(pm, name, PackageManager.GET_SIGNATURES, uid / 100000);
            ASN1Encodable[] arr = new ASN1Encodable[2];
            arr[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
                    new DEROctetString(packages[i].getBytes(StandardCharsets.UTF_8));
            arr[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(info.getLongVersionCode());
            packageInfoAA[i] = new DERSequence(arr);
            for (var s : info.signatures) {
                signatures.add(new Digest(dg.digest(s.toByteArray())));
            }
        }

        ASN1Encodable[] signaturesAA = new ASN1Encodable[signatures.size()];
        var i = 0;
        for (var d : signatures) {
            signaturesAA[i] = new DEROctetString(d.digest);
            i++;
        }

        ASN1Encodable[] applicationIdAA = new ASN1Encodable[2];
        applicationIdAA[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
                new DERSet(packageInfoAA);
        applicationIdAA[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
                new DERSet(signaturesAA);

        return new DEROctetString(new DERSequence(applicationIdAA).getEncoded());
    }

    record Digest(byte[] digest) {
        @Override
        public boolean equals(@Nullable Object o) {
            if (o instanceof Digest d)
                return Arrays.equals(digest, d.digest);
            return false;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }

    record KeyBox(PEMKeyPair pemKeyPair, KeyPair keyPair, List<Certificate> certificates) {
    }

    public static class KeyGenParameters {
        public int keySize;
        public int algorithm;
        public BigInteger certificateSerial;
        public Date certificateNotBefore;
        public Date certificateNotAfter;
        public X500Name certificateSubject;

        public BigInteger rsaPublicExponent;
        public int ecCurve;
        public String ecCurveName;

        public List<Integer> purpose = new ArrayList<>();
        public List<Integer> digest = new ArrayList<>();

        public byte[] attestationChallenge;
        public byte[] brand;
        public byte[] device;
        public byte[] product;
        public byte[] manufacturer;
        public byte[] model;
        public byte[] serial;
        public byte[] imei1, imei2;
        public byte[] meid;
        public byte[] attestationApplicationId;
        
        // Additional security tags
        public boolean noAuthRequired = true;
        public boolean rollbackResistance = false;
        public boolean earlyBootOnly = false;
        public boolean deviceUniqueAttestation = false;

        public KeyGenParameters() {
        }

        public KeyGenParameters(KeyParameter[] params) {
            for (var kp : params) {
                Logger.d("kp: " + kp.tag);
                var p = kp.value;
                switch (kp.tag) {
                    case Tag.KEY_SIZE -> keySize = p.getInteger();
                    case Tag.ALGORITHM -> algorithm = p.getAlgorithm();
                    case Tag.CERTIFICATE_SERIAL -> certificateSerial = new BigInteger(p.getBlob());
                    case Tag.CERTIFICATE_NOT_BEFORE ->
                            certificateNotBefore = new Date(p.getDateTime());
                    case Tag.CERTIFICATE_NOT_AFTER ->
                            certificateNotAfter = new Date(p.getDateTime());
                    case Tag.CERTIFICATE_SUBJECT ->
                            certificateSubject = new X500Name(new X500Principal(p.getBlob()).getName());
                    case Tag.RSA_PUBLIC_EXPONENT ->
                            rsaPublicExponent = new BigInteger(String.valueOf(p.getLongInteger()));
                    case Tag.EC_CURVE -> {
                        ecCurve = p.getEcCurve();
                        ecCurveName = getEcCurveName(ecCurve);
                    }
                    case Tag.PURPOSE -> purpose.add(p.getKeyPurpose());
                    case Tag.DIGEST -> digest.add(p.getDigest());
                    case Tag.ATTESTATION_CHALLENGE -> attestationChallenge = p.getBlob();
                    case Tag.ATTESTATION_ID_BRAND -> brand = p.getBlob();
                    case Tag.ATTESTATION_ID_DEVICE -> device = p.getBlob();
                    case Tag.ATTESTATION_ID_PRODUCT -> product = p.getBlob();
                    case Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = p.getBlob();
                    case Tag.ATTESTATION_ID_MODEL -> model = p.getBlob();
                    case Tag.ATTESTATION_ID_SERIAL -> serial = p.getBlob();
                    case Tag.ATTESTATION_ID_IMEI -> imei1 = p.getBlob();
                    case Tag.ATTESTATION_ID_SECOND_IMEI -> imei2 = p.getBlob();
                    case Tag.ATTESTATION_ID_MEID -> meid = p.getBlob();
                    case Tag.ATTESTATION_APPLICATION_ID -> attestationApplicationId = p.getBlob();
                    case Tag.NO_AUTH_REQUIRED -> noAuthRequired = true;
                    case Tag.ROLLBACK_RESISTANCE -> rollbackResistance = true;
                    case Tag.EARLY_BOOT_ONLY -> earlyBootOnly = true;
                    case Tag.DEVICE_UNIQUE_ATTESTATION -> deviceUniqueAttestation = true;
                }
            }
        }

        private static String getEcCurveName(int curve) {
            String res;
            switch (curve) {
                case EcCurve.CURVE_25519 -> res = "CURVE_25519";
                case EcCurve.P_224 -> res = "secp224r1";
                case EcCurve.P_256 -> res = "secp256r1";
                case EcCurve.P_384 -> res = "secp384r1";
                case EcCurve.P_521 -> res = "secp521r1";
                default -> throw new IllegalArgumentException("unknown curve");
            }
            return res;
        }

        public void setEcCurveName(int curve) {
            switch (curve) {
                case 224 -> this.ecCurveName = "secp224r1";
                case 256 -> this.ecCurveName = "secp256r1";
                case 384 -> this.ecCurveName = "secp384r1";
                case 521 -> this.ecCurveName = "secp521r1";
            }
        }
        
        // Getter methods for compatibility with SecurityLevelInterceptor
        public int[] getPurposes() {
            return purpose.stream().mapToInt(Integer::intValue).toArray();
        }
        
        public int[] getDigests() {
            return digest.stream().mapToInt(Integer::intValue).toArray();
        }
        
        public int getAlgorithm() {
            return algorithm;
        }
        
        public int getKeySize() {
            return keySize;
        }
        
        public int getEcCurve() {
            return ecCurve;
        }
        
        public boolean isNoAuthRequired() {
            return noAuthRequired;
        }
        
        public boolean isRollbackResistance() {
            return rollbackResistance;
        }
        
        public boolean isEarlyBootOnly() {
            return earlyBootOnly;
        }
        
        public boolean isDeviceUniqueAttestation() {
            return deviceUniqueAttestation;
        }
    }
}
