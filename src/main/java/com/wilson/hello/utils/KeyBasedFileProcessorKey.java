package com.wilson.hello.utils;


import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Iterator;

public class KeyBasedFileProcessorKey {

    /**
     * @param inputFileName   要解密的文件名
     * @param key             私钥
     * @param passwd          私钥解密key
     * @param defaultFileName 输出解密的文件
     * @throws IOException
     * @throws NoSuchProviderException
     */
    public static void decryptFile(String inputFileName, String key, char[] passwd, String defaultFileName) throws IOException, NoSuchProviderException {

        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));

        byte[] decode = Base64.getDecoder().decode(key);
        decryptFile(in, decode, passwd, defaultFileName);

        in.close();

    }

    /**
     * decrypt the passed in message stream
     */

    private static void decryptFile(InputStream in, byte[] keyIn, char[] passwd, String defaultFileName) throws IOException, NoSuchProviderException {

        in = PGPUtil.getDecoderStream(in);

        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;
            Object o = pgpF.nextObject();

            // the first object might be a PGP marker packet.
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            // find the secret key
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(keyIn, new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = PGPExampleUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                String outFileName = ld.getFileName();
                if (outFileName.length() == 0) {
                    outFileName = defaultFileName;
                } else {

                    /**
                     * modify 20160520
                     * set fileName
                     * 不同的系统可能源文件的包含的路径信息不同。
                     */

                    String separator = "";
                    if (outFileName.contains("/")) {
                        separator = "/";
                    } else if (outFileName.contains("\\")) {
                        separator = "\\";
                    }
                    String fileName = outFileName.substring(outFileName.lastIndexOf(File.separator) + 1);

                    String defseparator = "";
                    if (defaultFileName.contains("/")) {
                        defseparator = "/";
                    } else if (defaultFileName.contains("\\")) {
                        defseparator = "\\";
                    }

                    defaultFileName = defaultFileName.substring(0, defaultFileName.lastIndexOf(defseparator));
                    outFileName = defaultFileName + File.separator + fileName;

                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFileName));
                Streams.pipeAll(unc, fOut);
                fOut.close();

            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }
            } else {
                System.err.println("no message integrity check");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     * @param outputFileName     输出的加密文件名 2.pgp
     * @param inputFileName      输入的要加密的文件
     * @param encryKey           公钥
     * @param armor              true
     * @param withIntegrityCheck true
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public static void encryptFile(String outputFileName, String inputFileName, String encryKey, boolean armor, boolean withIntegrityCheck) throws IOException, NoSuchProviderException, PGPException {

        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decode = decoder.decode(encryKey);
        PGPPublicKey encKey = PGPExampleUtil.readPublicKey(new ByteArrayInputStream(decode));

        encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);

        out.close();

    }

    private static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck) throws IOException, NoSuchProviderException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        try {
            byte[] bytes = PGPExampleUtil.compressFile(fileName, CompressionAlgorithmTags.ZIP);
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck)
                            .setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            OutputStream cOut = encGen.open(out, bytes.length);
            cOut.write(bytes);
            cOut.close();

            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }

    }

    public static void main(String[] args) throws Exception {

        String keyString = "mQGNBF+17PEBDAC5JJ0Ldw+pe1ORwhAoCsick2jlK62WWWfoX39l5E+0rqcqc77eI0PJYV9M8i2FbrkkwfFpNC8l6yzSIb3PV2WMz/5V0iomAKtE+3DDzMdV2TGnuwBPuRnHfzYN5SeSyUpQ+Tax+Rmn8OYy2mHjAMVXMkUvOvUPi7jli7fk0h8U5m6XZuxwhSNEIfsdxcb8+Z05zcwK5fRv2g/HwErlCgVYtwDdJLGdzxPaQeV5MRc67ExOpbZr5jlV9hc33ntSirj5Rgs6VB3PvDZO9oAHbdoRsGJBAC05xopXFj1paWGqdA0ooRUmgOmln5KJnOCmopwUG7unXDNUeOXD2dqiQwQBAOlIHgnWB9cw/pIbRHCgX2CYJrcgelh3XXK4lHtYBSQSm5wzANYhuDKM/RBXTnE2McJs+RiHl/dHsmKKTRsnDeEg2elkW2DCwKyT0QPXR14sqodEyLYBL4ImmBBsE2rMNXuiVjM/6JNLDQJvYv0hoSDq9DuS/uGMMljOsY8eiU0AEQEAAbQfbWFyY28zOTg3MyA8bWFyY28zOTg3M0AxNjMuY29tPokB1AQTAQgAPhYhBOfY0Yf4KbtqxTMo38PDtuX38RvqBQJftezxAhsDBQkDwmfPBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEMPDtuX38RvqZB8MAKNPWSDWyd+mXr1qRKUU1lz1CQXmJDgHSZN/v+9BVTkLRhP39wCD+AglTYrC+V0C6J4v9Snwqy1iBFX4CMLAjK0lN4OQ6KQRP8H4gqAC8M4/kx80KDYamYTKctTO/MyzTnckptnARLHo7TPDjfC/KOkOgwH77faVw47oVEgd8FKvLyq/unmhfuILyOSVk8Ps9j9FrJ/OJMFFWMQyzKhW1yoqZcHF46POgV361zolw9AFhvreN5ia8vaFsrVEFuNAAo1pzu+YXuOOBFkktK7MHoIglGWieg8aQYmvHAYDVws1FiNts/1k8qeXm+OvX5FbHiKK021/z/B0uQY9yhMhOJXI5K1Ah/7TRXb/e9TtAIQlBCqTy5+W20kVnTWxr0ywd8lw/BylpyZ0vLRLhESLcJJ9sB1fSY40GlhUboCuLlfzSvilmUcpwducIpY3QHY/05OMCoKFoP2/bY/Hfb7IfgXZL4j5jIBCMY5kEbYe0Ss5oJmS9eDPF1vRabGxg7FyzbkBjQRftezxAQwAu0Vh0ElP13ksounpskMrdHu49f+Dsdx56p9x250jPI3oe4ZqjhjWVN6CKxgwUbApFDjXbmNdAeAtz8LtgoMwZcU7NP/ZLQQr1qAqxQtYC0WWQzu2a/aZPDg4LgBwWNbzNMmq+ubyuzhBaxoNT7LNb5IHY65UJwYzWI9lMCwBSzkD9dLmYQ+yFZPZaqCVU8BtUSCiX+eYb3Rj0Y/wQM0yjjsVcjaBB9jQvu5RB57xzHTo2XovZggGo9GF9tAjan5NcLiXQgjBcOQnhh+NoB/PdP7WThtd65luzOLLa7PV9hWjHSYY5lM1IsG4eJjBnzaSiFaBGeinXN1CcdgUGu8DejjL7Evt+Gr3nIClld0Cg6tOGh7R5jaATQDVsZm8ooyg8CCwGQpv6H4m08VTt++9fSeczPFau2PjTnZgKHkVRvt1f/gBDwxo590D+vtQ1dkjb7s5dO0OWJ8qMx7Hcp9xerKb0j/C5LtoWmXvXAdkMhjUtGVzS7wyagDxSOdJg4ZdABEBAAGJAbwEGAEIACYWIQTn2NGH+Cm7asUzKN/Dw7bl9/Eb6gUCX7Xs8QIbDAUJA8JnzwAKCRDDw7bl9/Eb6rd6DACFuGv0lLRNh9oHQ/oniI+Cnz35jbL0aQGQHj0xS6V7qz2LTNBJAxcf56FX6tHAIYQWhuqmbDBah24DsruQdCIkhAfRoDnoJrRv+LFBk0kX3nxPIxmU6XFXfkeOHTemvaUqTeN91HtADjWtSraw6Kzk/RIAfjY3tEmEDSHDnLmFhZR1NJogxyU5kvG+qQIRP46zmgRK/B8GRJjCEk+i+sQOktgbvFVCZT7139RoJDQWmKIt34Lm8CxfO3/6RhdE3SE/sCukjifS4DB9ve2XmTjn0pRYUJoLgfMJt9N1Kv90fvqyCl/HCn/Hnlj3IzEs9y31uNRZmZyBiyxVDjDgjD4okMQnxl52LkIdYeDAYSoN9Tn36gY9wRsSKjjjf/K2ukDJN43HVs9bedvbrWda/ONoPY/W2g2XJY7pbHJdeZnR51rwIE8TTYL7KsX3HBgP1Gg8iIafElFvan7ms1nfGKFeeVj0Dd3fN+FP7SUG8JykiwiFYkMj1KiomTIuu/uMqyc=";
        String privateKeyString = "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";

        Security.addProvider(new BouncyCastleProvider());
        encryptFile("C:\\pgp\\testFiles\\New folder\\test1.txt.pgp", "C:\\pgp\\testFiles\\New folder\\test1.txt", keyString, true, true); // 加密文件
        decryptFile("C:\\pgp\\testFiles\\New folder\\test1.txt.pgp", privateKeyString, "MAYFLOWER39873".toCharArray(), "C:\\pgp\\testFiles\\New folder\\test3.txt");// 解密文件

    }

}