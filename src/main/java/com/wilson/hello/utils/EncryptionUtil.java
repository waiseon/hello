package com.wilson.hello.utils;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@Component
public class EncryptionUtil {

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    @Value("${cpp.miles.encryption.algo}")
    public String encryptAlgo;

    @Value("${cpp.miles.encryption.key}")
    private String key;

    @Value("${cpp.miles.encryption.algorithm}")
    private String algorithm;

    private ObjectMapper objectMapper;

    public <T> T decrypt(String encryptedStr, TypeReference<T> typeReference) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(UTF_8), algorithm);
        Cipher cipher = Cipher.getInstance(encryptAlgo);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] originalBytes = cipher.doFinal(Base64.decodeBase64(encryptedStr));

        GZIPInputStream gzipis = new GZIPInputStream(new ByteArrayInputStream(originalBytes));
        ObjectMapper mapper = getObjectMapper();
        return mapper.readValue(IOUtils.toByteArray(gzipis), typeReference);
    }

    @Deprecated
    public <T> T decrypt(String encryptedData, Class<T> clazz) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecretKeySpec skeySpec = new SecretKeySpec(Base64.decodeBase64(key), algorithm);
        Cipher cipher = Cipher.getInstance(encryptAlgo);
        ObjectMapper mapper = getObjectMapper();

        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] originalBytes = cipher.doFinal(Base64.decodeBase64(encryptedData));
        return mapper.readValue(originalBytes, clazz);
    }

    public <T> String encrypt(T object) throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        ObjectMapper mapper = getObjectMapper();
        String objectStr = mapper.writeValueAsString(object);

        // Create cipher for encryption
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(UTF_8), algorithm);
        Cipher cipher = Cipher.getInstance(encryptAlgo);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Compression
        byte[] objectStrByte = objectStr.getBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(objectStrByte.length);
        GZIPOutputStream gzos = new GZIPOutputStream(bos);
        gzos.write(objectStrByte);
        gzos.flush();
        gzos.close();

        // Encryption
        byte[] result = cipher.doFinal(bos.toByteArray());

        return Base64.encodeBase64String(result);
    }

    private ObjectMapper getObjectMapper() {
        if (objectMapper == null) {
            objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        }
        return objectMapper;
    }

}
