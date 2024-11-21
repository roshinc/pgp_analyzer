package dev.roshin.pgp_analyzer;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

public class PGPFileGenerator {
    public static KeyPairInfo generateKeyPair(String userId, String outputPath, char[] password) throws Exception {
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(
                BigInteger.valueOf(0x10001),
                new SecureRandom(),
                2048,
                12
        ));

        PGPKeyPair keyPair = new BcPGPKeyPair(
                PGPPublicKey.RSA_GENERAL,
                kpg.generateKeyPair(),
                new Date()
        );

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                keyPair,
                userId,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                null,
                null,
                new BcPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).build(password)
        );

        PGPSecretKeyRing secretKeyRing = keyRingGen.generateSecretKeyRing();
        PGPPublicKeyRing publicKeyRing = keyRingGen.generatePublicKeyRing();

        // Write public key
        try (OutputStream out = new FileOutputStream(outputPath + ".asc")) {
            try (ArmoredOutputStream armOut = new ArmoredOutputStream(out)) {
                publicKeyRing.encode(armOut);
            }
        }

        // Write private key
        try (OutputStream out = new FileOutputStream(outputPath + ".sec")) {
            try (ArmoredOutputStream armOut = new ArmoredOutputStream(out)) {
                secretKeyRing.encode(armOut);
            }
        }

        return new KeyPairInfo(secretKeyRing.getSecretKey(), publicKeyRing.getPublicKey());
    }

    public static void encryptAndSignFile(
            String inputFile,
            String outputFile,
            PGPPublicKey encryptionKey,
            PGPSecretKey signingKey,
            char[] signingKeyPassword) throws Exception {

        // Get private key for signing
        PGPPrivateKey pgpPrivKey = signingKey.extractPrivateKey(
                new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                        .build(signingKeyPassword));

        try (OutputStream out = new FileOutputStream(outputFile)) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
            );
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey));

            try (OutputStream encOut = encGen.open(out, new byte[1 << 16])) {
                PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(
                        CompressionAlgorithmTags.ZIP);

                try (OutputStream compOut = compGen.open(encOut)) {
                    PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                            new BcPGPContentSignerBuilder(
                                    signingKey.getPublicKey().getAlgorithm(),
                                    HashAlgorithmTags.SHA256
                            )
                    );
                    sigGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

                    PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
                    try (InputStream in = new FileInputStream(inputFile);
                         OutputStream litOut = litGen.open(
                                 compOut,
                                 PGPLiteralData.BINARY,
                                 new File(inputFile).getName(),
                                 new Date(),
                                 new byte[1 << 16])) {

                        byte[] buffer = new byte[1 << 16];
                        int len;
                        while ((len = in.read(buffer)) > 0) {
                            litOut.write(buffer, 0, len);
                            sigGen.update(buffer, 0, len);
                        }
                    }
                    sigGen.generate().encode(compOut);
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        char[] encryptionKeyPass = "encryption".toCharArray();
        char[] signingKeyPass = "signing".toCharArray();

        // Generate encryption key pair
        KeyPairInfo encryptionKey = generateKeyPair("encrypt@example.com", "encryption_key", encryptionKeyPass);

        // Generate separate signing key pair
        KeyPairInfo signingKey = generateKeyPair("signing@example.com", "signing_key", signingKeyPass);

        // Create a sample file
        try (FileWriter writer = new FileWriter("sample.txt")) {
            writer.write("This is a test file to encrypt and sign");
        }

        // Encrypt and sign the file
        encryptAndSignFile(
                "sample.txt",
                "encrypted.gpg",
                encryptionKey.publicKey,
                signingKey.secretKey,
                signingKeyPass
        );
    }

    public static class KeyPairInfo {
        public final PGPSecretKey secretKey;
        public final PGPPublicKey publicKey;

        public KeyPairInfo(PGPSecretKey secretKey, PGPPublicKey publicKey) {
            this.secretKey = secretKey;
            this.publicKey = publicKey;
        }
    }
}