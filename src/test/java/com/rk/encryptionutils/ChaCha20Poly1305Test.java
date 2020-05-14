package com.rk.encryptionutils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

public class ChaCha20Poly1305Test
{

  private int KEY_LEN = 256; // bits

  @Test
  public void whenDecryptCalled_givenEncryptedTest_returnsDecryptedBytes() throws Exception
  {

    char[] input = { 'e', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n' };
    byte[] inputBytes = convertInputToBytes(input);

    KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
    keyGen.init(KEY_LEN, SecureRandom.getInstanceStrong());
    SecretKey secretKey = keyGen.generateKey();

    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "ChaCha20");
    ChaCha20Poly1305.clearSecret(secretKey);

    byte[] encryptedBytes = ChaCha20Poly1305.encrypt(inputBytes, secretKeySpec);
    byte[] decryptedBytes = ChaCha20Poly1305.decrypt(encryptedBytes, secretKeySpec);

    ChaCha20Poly1305.clearSecret(secretKeySpec);

    assertArrayEquals(inputBytes, decryptedBytes);

  }

  private byte[] convertInputToBytes(char[] input)
  {
    CharBuffer charBuf = CharBuffer.wrap(input);
    ByteBuffer byteBuf = Charset.forName(Charset.defaultCharset().name()).encode(charBuf);
    byte[] inputBytes = byteBuf.array();
    charBuf.clear();
    byteBuf.clear();
    return inputBytes;
  }
}