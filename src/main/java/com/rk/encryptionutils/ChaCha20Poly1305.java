
/***********************************************************************************
 * <pre>
 * Class: ChaCha20Poly1305
 * Package: com.rk.encryptionutils
 * 
 * </pre>
 * 
 * @beaninfo 
 * Description: Class with a collection of 
 *              ChaCha20-Poly1305 utilities
 * 
 * @author rknechtel
 * @created May 13, 2020
 * 
 *  <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel             May 13 2020   Created
 * </pre>
 * 
 **********************************************************************************/
/*********************************************************
 * <pre>
 *              LICENSE
 *              
 * This program is free software; you can redistribute
 * it and/or modify it under the terms of the GNU
 * General Public License as published by  the Free
 * Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General
 * Public License along with this method; if not,
 * write to the
 * Free Software Foundation, Inc., 
 * 675 Mass Ave,
 * Cambridge, MA 02139, USA.
 * Or on the web at:
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * </pre>
 *********************************************************/
/**
 * <pre>
* General Info:
* Chacha Cipher is a stream cipher which uses a 256-bit key and a 64-bit nonce [paper]. 
* Currently AES has a virtual monopoly on secret key encryption. There would be major problems, 
* though, if this was cracked. Along with this AES has been shown to be weak around cache-collision 
* attacks. Google thus propose ChaCha20 as an alternative, and actively use it within TLS connections. 
* Currently it is three times faster than software-enabled AES, and is not sensitive to timing attacks. 
* It operates by creating a key stream which is then X-ORed with the plaintext. 
* It has been standardised with RFC 7539.
* https://tools.ietf.org/html/rfc7539
* 
* ChaCha20-Poly1305 is an AEAD, Authenticated Encryption with Additional Data cipher. 
* AEADs support two operations: "seal" and "open".
* 
* </pre>
*********************************************************/
/***************************************************************
 * <pre>
 * The inputs to ChaCha20 encryption, specified by RFC 7539, are:
 * 1) A 256-bit secret key.
 * 2) A 96-bit nonce.
 * 3) A 32-bit initial count.
 * The IV property is used to specify the chacha20 nonce.
 * For a 96-bit nonce, the IV should be 12 bytes in length.
 * 
 * Note: 
 * Some implementations of chacha20, such as that used internally by SSH,
 * use a 64-bit nonce and 64-bit count. 
 * To do chacha20 encryption in this way, simply provide 8 bytes 
 * for the IV instead of 12 bytes.
 *</pre>
 ****************************************************************/
/***************************************************************
 * <pre>
 * The possible reasons for using ChaCha20-Poly1305 which is a
 * stream cipher based authenticated encryption algorithm
 * 1. If the CPU does not provide dedicated AES instructions,
 *    ChaCha20 is faster than AES
 * 2. ChaCha20 is not vulnerable to cache-collision timing 
 *    attacks unlike AES
 * 3. Since the nonce is not required to be random. There is
 *    no overhead for generating cryptographically secured
 *    pseudo random number
 *</pre>
 ****************************************************************/

package com.rk.encryptionutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ChaCha20Poly1305 {

  private static final String ENCRYPT_ALGO = "ChaCha20-Poly1305/None/NoPadding";

  private static final int KEY_LEN = 256;

  private static final int NONCE_LEN = 12; //bytes

  private static final BigInteger NONCE_MIN_VAL = new BigInteger("100000000000000000000000", 16);
  private static final BigInteger NONCE_MAX_VAL = new BigInteger("ffffffffffffffffffffffff", 16);

  private static BigInteger nonceCounter = NONCE_MIN_VAL;

    /************************************************************
   * <pre>
   * Method: encrypt()
   * Description: Will encrypt a passed in String using ChaCha20
   * </pre>
   * 
   * @param (byte[]) pValue
   * @param (SecretKeySpec) pSecretKey
   * @return (byte[])
   ***********************************************************/
  public static byte[] encrypt(byte[] pValue, SecretKeySpec pSecretKey) throws Exception 
  {
    Objects.requireNonNull(pValue, "Input Value cannot be null");
    Objects.requireNonNull(pSecretKey, "Secret Key cannot be null");

    if (pValue.length == 0) 
    {
      throw new IllegalArgumentException("Length of the Value cannot be 0");
    }

    if (pSecretKey.getEncoded().length * 8 != KEY_LEN) 
    {
      throw new IllegalArgumentException("Size of Secret Key must be 256 bits");
    }

    Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

    byte[] nonce = getNonce();

    IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

    cipher.init(Cipher.ENCRYPT_MODE, pSecretKey, ivParameterSpec);

    byte[] messageCipher = cipher.doFinal(pValue);

    // Prepend the nonce with the message cipher
    byte[] cipherText = new byte[messageCipher.length + NONCE_LEN];
    System.arraycopy(nonce, 0, cipherText, 0, NONCE_LEN);
    System.arraycopy(messageCipher, 0, cipherText, NONCE_LEN, messageCipher.length);

    return cipherText;
  } // End of encrypt()

    /************************************************************
   * <pre>
   * Method: decrypt()
   * Description: This method Decrpyt a passed in String using 
   *              ChaCha20  
   * </pre>
   * 
   * @param (byte[]) pValue
   * @param (SecretKeySpec) pKey
   * @return (byte[])
   ***********************************************************/
  public static byte[] decrypt(byte[] pValue, SecretKeySpec pKey) throws Exception
  {
    Objects.requireNonNull(pValue, "Input value cannot be null");
    Objects.requireNonNull(pKey, "Secret Key cannot be null");

    if (pValue.length == 0) 
    {
      throw new IllegalArgumentException("Input array cannot be empty");
    }

    byte[] nonce = new byte[NONCE_LEN];
    System.arraycopy(pValue, 0, nonce, 0, NONCE_LEN);

    byte[] messageCipher = new byte[pValue.length - NONCE_LEN];
    System.arraycopy(pValue, NONCE_LEN, messageCipher, 0, pValue.length - NONCE_LEN);

    IvParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

    Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
    cipher.init(Cipher.DECRYPT_MODE, pKey, ivParameterSpec);

    return cipher.doFinal(messageCipher);
  } // End of decrypt()


  /************************************************************
   * <pre>
   * Method: getNonce()
   * Description: This method creates the 96 bit nonce. 
   * 
   * Note:
   * A 96 bit nonce 
   * is required for ChaCha20-Poly1305. The nonce is not 
   * a secret. The only requirement being it has to be 
   * unique for a given key. The following function implements 
   * a 96 bit counter which when invoked always increments 
   * the counter by one.
   * 
   * </pre>
   * 
   * @return (byte[])
   ***********************************************************/
  public static byte[] getNonce() 
  {
    if (nonceCounter.compareTo(NONCE_MAX_VAL) == -1) 
    {
      return nonceCounter.add(BigInteger.ONE).toByteArray();
    } 
    else 
    {
      nonceCounter = NONCE_MIN_VAL;
      return NONCE_MIN_VAL.toByteArray();
    }

  } // End of getNonce() 

  /************************************************************
   * <pre>
   * Method: clearSecret()
   * Description: Will clear the secret key on the ChaCha20 
   *              object
   * Note:
   * Strings should not be used to hold the clear text message or the key, 
   * as Strings go in the String pool and they will show up in a heap dump. 
   * For the same reason, the client calling these encryption or decryption 
   * methods should clear all the variables or arrays holding the message
   * or the key after they are no longer needed. Since Java 8 does not 
   * provide an easy mechanism to clear the key from {@code SecretKeySpec}, 
   * this method uses reflection to clear the key
   * 
   * </pre>
   * @param key The secret key used to do the encryption
   * @throws IllegalArgumentException
   * @throws IllegalAccessException
   * @throws NoSuchFieldException
   * @throws SecurityException
   ***********************************************************/
  @SuppressWarnings("unused")
  public static void clearSecret(Destroyable key) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
  {
    Field keyField = key.getClass().getDeclaredField("key");
    keyField.setAccessible(true);
    byte[] encodedKey = (byte[]) keyField.get(key);
    Arrays.fill(encodedKey, Byte.MIN_VALUE);

  } // End of clearSecret()

  /************************************************************
   * <pre>
   * Method: geChaCha20Key()
   * Description: Will create A ChaCha20 
   *              256-bit secret key (32 bytes)
   * </pre>
   * 
   * @return (SecretKeySpec)
   * @throws NoSuchAlgorithmException
   ***********************************************************/
  public SecretKeySpec geChaCha20Key() throws NoSuchAlgorithmException 
  {
    KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
    keyGen.init(KEY_LEN, SecureRandom.getInstanceStrong());
    SecretKey secretKey = keyGen.generateKey();
    SecretKeySpec newSecretkey = new SecretKeySpec(secretKey.getEncoded(), "ChaCha20");

    return newSecretkey;
  } // End of geChaCha20Key()

  /******************************************************************
   * <pre>
   * Method: saveChaCha20Key()
   * Description: Will save an ChaCha20 encryption key to filesystem
   * Example: C:\temp\myKeyFile.key
   * </pre>
   * 
   * @param (SecretKey) pKey
   * @param (File) pFile
   * @throws IOException
   ******************************************************************/
  private void saveChaCha20Key(SecretKeySpec pKey, File pFile) throws IOException, FileNotFoundException
  {
    byte[] encoded = pKey.getEncoded();
    String data = new BigInteger(1, encoded).toString(16);
    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(pFile, false));
    out.writeObject(data);
    out.flush();
    out.close();

  } // End of saveChaCha20Key()

  /******************************************************************
   * <pre>
   * Method: loadChaCha20Key()
   * Description: Will load an ChaCha20 key file from the filesystem
   *              Example: C:\temp\myKeyFile.key
   * </pre>
   * 
   * @param (String) pFile
   * @return (SecretKey)
   * @throws IOException
   ****************************************************************/
  public SecretKeySpec loadChaCha20Key(String pFile) throws IOException
  {

    String sKey = null;
    FileInputStream fis = new FileInputStream(pFile);
    ObjectInputStream ois = new ObjectInputStream(fis);

    try
    {
      sKey = (String) ois.readObject();
    }
    catch (ClassNotFoundException e)
    {
      e.printStackTrace();
    }
    ois.close();

    byte[] encoded = new BigInteger(sKey, 16).toByteArray();
    SecretKeySpec key = new SecretKeySpec(encoded, "ChaCha20");

    return key;
  } // End of loadChaCha20Key()

} // End of ChaCha20Poly1305