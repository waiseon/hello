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
    public static void decryptFile(

            String inputFileName,

            String key,

            char[] passwd,

            String defaultFileName)

            throws IOException, NoSuchProviderException {

        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));

        byte[] decode = Base64.getDecoder().decode(key);
        decryptFile(in, decode, passwd, defaultFileName);


        in.close();

    }

    /**
     * decrypt the passed in message stream
     */

    private static void decryptFile(

            InputStream in,

            byte[] keyIn,

            char[] passwd,

            String defaultFileName)

            throws IOException, NoSuchProviderException {

        in = PGPUtil.getDecoderStream(in);

        try {

            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);

            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();

//

// the first object might be a PGP marker packet.

//

            if (o instanceof PGPEncryptedDataList) {

                enc = (PGPEncryptedDataList) o;

            } else {

                enc = (PGPEncryptedDataList) pgpF.nextObject();

            }

//

// find the secret key

//

            Iterator it = enc.getEncryptedDataObjects();

            PGPPrivateKey sKey = null;

            PGPPublicKeyEncryptedData pbe = null;

            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(

                    keyIn, new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {

                pbe = (PGPPublicKeyEncryptedData) it.next();

                sKey = PGPExampleUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);

            }

            if (sKey == null) {

                throw new IllegalArgumentException("secret key for message not found.");

            }

            InputStream clear = pbe
                    .getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

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
                     *
                     * modify 20160520
                     *
                     * set fileName
                     *
                     * 不同的系统可能源文件的包含的路径信息不同。
                     *
                     */

                    String separator = "";

                    if (outFileName.contains("/")) {

                        separator = "/";

                    } else if (outFileName.contains("\\")) {

                        separator = "\\";

                    }

                    String fileName = outFileName.substring(outFileName.lastIndexOf(File.separator) + 1);

                    //

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
        PGPPublicKey encKey = PGPExampleUtil.readPublicKey(decode);

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

    public static void main(

            String[] args)

            throws Exception {
        String keyString = "mQENBF+2GmgBCADBVW1oQzvU9AItcFF99qNFmNmRdScNsOygA9UJx2oFBLzhP/ukgqFrdG1lx/epptF9rZVRBc/l2mplBIaeWFGgeSZC8pWrakUydk7fEKuSgoyNCIMy4FDiKzp+37WXxFas6VauyQibVEZ7IEIit+Ftz2WrQkFJ0/LURE/jV4JvsvCaRPVB0AP2cqC/Q7z5Bb+dZjmpfCtm1EZkrmLDj+vniePbjZ5af4eG8px2+eKLQp9520Eb3+bwYRv7EZpZWIafSyKB9G+ml8sGGAjuHRf0T1uz16fA6CtYh0pT2BZFUM1JTA297YTkOYqV30rtnj1u5zuqcreJGnFD+AdTqeRRABEBAAG0CHdhdGhkYXRhiQEcBBABAgAGBQJfthpoAAoJEOqvNRExgK2K9/MIALmDFuhusxAmOupjFgPUdd7GsdbdzUN+FIJBQbWKHX3FR5FxhmmWAlfVcjDFAjKaZ7dTrcitwusJt87pZOeBs/Mq1MYWUfA0JuXXSHVwU/l8wUCahROQv8+Q47K/1K4kWz18a9g0dEW0onf4IIPZav19nRJ4D48DEX0fzL3s7mAuVUi0ZVdqKhmHONf238SCAbKdcSJaaEjrC96xz7rlj3fyKzdZORJd9Hsr150KoX8Io83iwjPr2XYbriyO4gDJJa+6PL5MTC+ZxdXSV4/QmJEu1KuG4EGHYvWGP/O7rlgVInQ/iBAY2vkt+/u5Bht2PUQk//+JVAKtuTPRhJ7bh0w=";

        String privateKeyString = "lQO+BF+2GmgBCADBVW1oQzvU9AItcFF99qNFmNmRdScNsOygA9UJx2oFBLzhP/ukgqFrdG1lx/epptF9rZVRBc/l2mplBIaeWFGgeSZC8pWrakUydk7fEKuSgoyNCIMy4FDiKzp+37WXxFas6VauyQibVEZ7IEIit+Ftz2WrQkFJ0/LURE/jV4JvsvCaRPVB0AP2cqC/Q7z5Bb+dZjmpfCtm1EZkrmLDj+vniePbjZ5af4eG8px2+eKLQp9520Eb3+bwYRv7EZpZWIafSyKB9G+ml8sGGAjuHRf0T1uz16fA6CtYh0pT2BZFUM1JTA297YTkOYqV30rtnj1u5zuqcreJGnFD+AdTqeRRABEBAAH+AwMCEzsFq+y1UB9gHgtFIEfJnuLTLpcyw6QDU1OeQgzinRRlLfSe2oXh9iW1aRYfRl13G6640WVhmw4kZxLZJ2sK6/6u5gCyxlo/rPrbc9BCaSPeFjyKei/0hlV/yqHCKj/A+kpQ9ajRseofxlNIrZbxBfLhxYgP0heNYHQBsEo474xhsJt/oWbbXGT6xbBH0Fbq9LI9P2QL20B5oRqYnJ/KwDz0x3/9BCEqu+YrTk/rSczCNDcBsO2jqzhotDiybdOuoYdru/7UWOA0XkcsjOnSVgvRsaFd6SD8v2N2hiQ/VtNkHTcN18h4kuggiWag/jrgDROXvzCWVgbH9TduavnZE5RNWeSLWuVa551BEW4016+Md3tcH484Z9ARU6cY/WTjL16eVMgltNrAPgnwsxBdwvRpnm9ptNewH4mBCerO5OJ0E6gb46sMmtWlTC+oddzh7jpKOBqm7/wdKd/cI6+Lb3l+S8LqzIv+JH/vqa+MkXppDyYQomyg/R2LuhHyjQVL7z5XOK8paD8kVnXFva2FcrkH9YmdCkksqfYGG5L31l4Ic+4DW40lkua/47XgC0YKnuOeFf+pQZBOV+cEiqipErbEENqftIKiok97csuw6apYasPRJ0Aoac3kmca92/ZRwN/s1o6rPMzODyPB0jHWvFSqBeiRZsvUbF6N2zVOhC0h3U2SzqnyA9xwurKumT7IzzvWEfPpoITrMfpNDhKqMLrxiXqxJI4TenzL1+6Y7cYllwFFScxyi07IGgwBjTrHg++yBn0T5bCsX8V1kdf/JRcC1RwXnx+VsSX2NpgQLSC5Dsc+gii5nRb954vS/EDxce6MPBJGXo4tIOKolUiUon1cNC0Ag+nwShU+9Dwgo20MzR1iAyT/cZNY+EPsS9OJ753+GOh7TwFmQlMfWbQId2F0aGRhdGGJARwEEAECAAYFAl+2GmgACgkQ6q81ETGArYr38wgAuYMW6G6zECY66mMWA9R13sax1t3NQ34UgkFBtYodfcVHkXGGaZYCV9VyMMUCMppnt1OtyK3C6wm3zulk54Gz8yrUxhZR8DQm5ddIdXBT+XzBQJqFE5C/z5Djsr/UriRbPXxr2DR0RbSid/ggg9lq/X2dEngPjwMRfR/MvezuYC5VSLRlV2oqGYc41/bfxIIBsp1xIlpoSOsL3rHPuuWPd/IrN1k5El30eyvXnQqhfwijzeLCM+vZdhuuLI7iAMklr7o8vkxML5nF1dJXj9CYkS7Uq4bgQYdi9YY/87uuWBUidD+IEBja+S37+7kGG3Y9RCT//4lUAq25M9GEntuHTA==";

        Security.addProvider(new BouncyCastleProvider());
        encryptFile("c://2.pgp", "c://2.txt", keyString, true, true); // 加密文件
        decryptFile("c://2.pgp", privateKeyString, "123456789".toCharArray(), "c://3.txt");// 解密文件

    }

}