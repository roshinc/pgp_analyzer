package dev.roshin.pgp_analyzer;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;

public class PGPAnalyzer {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Please provide the path to the file to analyze.");
            return;
        }

        String filePath = args[0];
        String ascKeyPath = args.length > 1 ? args[1] : null;

        try {
            analyzeFile(filePath, ascKeyPath);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void analyzeFile(String filePath, String ascKeyPath) throws Exception {
        InputStream in = new BufferedInputStream(new FileInputStream(filePath));
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        Object object = null;
        boolean isEncrypted = false;
        boolean isSigned = false;

        while ((object = pgpFactory.nextObject()) != null) {
            if (object instanceof PGPEncryptedDataList) {
                isEncrypted = true;
                System.out.println("The file is encrypted.");
                PGPEncryptedDataList encList = (PGPEncryptedDataList) object;
                Iterator<?> it = encList.getEncryptedDataObjects();
                while (it.hasNext()) {
                    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) it.next();
                    System.out.printf("Requires key ID: 0x%016X for decryption.%n", encData.getKeyID());
                    if (ascKeyPath != null) {
                        checkKeyInKeyring(encData.getKeyID(), ascKeyPath);
                    }
                }
            } else if (object instanceof PGPOnePassSignatureList) {
                isSigned = true;
                System.out.println("The file contains a one-pass signature.");
                PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) object;
                for (int i = 0; i < opsList.size(); i++) {
                    PGPOnePassSignature ops = opsList.get(i);
                    System.out.printf("Signature requires key ID: 0x%016X for verification.%n", ops.getKeyID());
                    if (ascKeyPath != null) {
                        checkKeyInKeyring(ops.getKeyID(), ascKeyPath);
                    }
                }
            } else if (object instanceof PGPSignatureList) {
                isSigned = true;
                System.out.println("The file contains signature(s).");
                PGPSignatureList sigList = (PGPSignatureList) object;
                for (int i = 0; i < sigList.size(); i++) {
                    PGPSignature signature = sigList.get(i);
                    System.out.printf("Signature requires key ID: 0x%016X for verification.%n", signature.getKeyID());
                    if (ascKeyPath != null) {
                        checkKeyInKeyring(signature.getKeyID(), ascKeyPath);
                    }
                }
            } else if (object instanceof PGPLiteralData) {
                // Literal data; actual content
            } else if (object instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) object;
                analyzeCompressedData(cData.getDataStream(), ascKeyPath);
            } else {
                System.out.println("Encountered an unknown PGP object.");
            }
        }

        if (!isEncrypted && !isSigned) {
            System.out.println("The file is not encrypted or signed.");
        }

        in.close();
    }

    public static void analyzeCompressedData(InputStream compressedStream, String ascKeyPath) throws Exception {
        PGPObjectFactory pgpFactory = new PGPObjectFactory(compressedStream, new BcKeyFingerprintCalculator());
        Object object = null;

        while ((object = pgpFactory.nextObject()) != null) {
            if (object instanceof PGPOnePassSignatureList) {
                System.out.println("The compressed data contains a one-pass signature.");
                PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) object;
                for (int i = 0; i < opsList.size(); i++) {
                    PGPOnePassSignature ops = opsList.get(i);
                    System.out.printf("Signature requires key ID: 0x%016X for verification.%n", ops.getKeyID());
                    if (ascKeyPath != null) {
                        checkKeyInKeyring(ops.getKeyID(), ascKeyPath);
                    }
                }
            } else if (object instanceof PGPSignatureList) {
                System.out.println("The compressed data contains signature(s).");
                PGPSignatureList sigList = (PGPSignatureList) object;
                for (int i = 0; i < sigList.size(); i++) {
                    PGPSignature signature = sigList.get(i);
                    System.out.printf("Signature requires key ID: 0x%016X for verification.%n", signature.getKeyID());
                    if (ascKeyPath != null) {
                        checkKeyInKeyring(signature.getKeyID(), ascKeyPath);
                    }
                }
            } else if (object instanceof PGPLiteralData) {
                // Reached actual content; no further action
            } else if (object instanceof PGPCompressedData) {
                // Handle nested compressed data
                PGPCompressedData cData = (PGPCompressedData) object;
                analyzeCompressedData(cData.getDataStream(), ascKeyPath);
            } else {
                System.out.println("Encountered an unknown PGP object inside compressed data.");
            }
        }
    }

    public static void checkKeyInKeyring(long keyID, String ascKeyPath) throws Exception {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(ascKeyPath));
        keyIn = PGPUtil.getDecoderStream(keyIn);
        boolean keyFound = false;

        try {
            // Try loading as a public key ring collection
            PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(
                    keyIn, new BcKeyFingerprintCalculator());

            PGPPublicKey pubKey = pgpPubRingCollection.getPublicKey(keyID);
            if (pubKey != null) {
                System.out.println("The required key is present in the provided ASC public key file.");
                keyFound = true;
            }
        } catch (PGPException e) {
            // If loading as public keys fails, try loading as secret keys
            keyIn.close();
            keyIn = new BufferedInputStream(new FileInputStream(ascKeyPath));
            keyIn = PGPUtil.getDecoderStream(keyIn);

            try {
                PGPSecretKeyRingCollection pgpSecRingCollection = new PGPSecretKeyRingCollection(
                        keyIn, new BcKeyFingerprintCalculator());

                PGPSecretKey secKey = pgpSecRingCollection.getSecretKey(keyID);
                if (secKey != null) {
                    System.out.println("The required key is present in the provided ASC secret key file.");
                    keyFound = true;
                }
            } catch (PGPException ex) {
                // The key file is neither public nor secret key ring collection
                System.out.println("The provided ASC key file is neither a valid public nor secret key ring collection.");
            }
        } finally {
            keyIn.close();
        }

        if (!keyFound) {
            System.out.println("The required key is NOT present in the provided ASC key file.");
        }
    }

}
