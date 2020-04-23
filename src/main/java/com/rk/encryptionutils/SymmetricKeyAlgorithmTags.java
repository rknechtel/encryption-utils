/***********************************************************************************
 * <pre>
 * Class: SymmetricKeyAlgorithmTags.java
 * Package: com.rk.encryptionutils
 *
 * </pre>
 * @beaninfo Description:
 *
 * @author rknechtel
 * @created May 8, 2016
 *
 * <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 * </pre>
 *  rknechtel              May 8, 2016        Created
 *
 **********************************************************************************/
package com.rk.encryptionutils;


public interface SymmetricKeyAlgorithmTags
{
  /**
   * <pre>
   * By default, PGP uses IDEA
   * The corporate version of PGP uses AES256. 
   * They all use CFB mode with no padding.
   * 
   * </pre>
   */
  public static final int NULL = 0;        // Plaintext or unencrypted data
  public static final int IDEA = 1;        // IDEA [IDEA] (International Data Encryption Algorithm)
  public static final int TRIPLE_DES = 2;  // Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
  public static final int CAST5 = 3;       // CAST5 (128 bit key, as per RFC 2144)
  public static final int BLOWFISH = 4;    // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
  public static final int SAFER = 5;       // SAFER-SK128 (13 rounds) [SAFER]
  public static final int DES = 6;         // Reserved for DES/SK
  public static final int AES_128 = 7;     // Reserved for AES with 128-bit key
  public static final int AES_192 = 8;     // Reserved for AES with 192-bit key
  public static final int AES_256 = 9;     // Reserved for AES with 256-bit key
  public static final int TWOFISH = 10;    // Reserved for Twofish
} // End of Interface SymmetricKeyAlgorithmTags
