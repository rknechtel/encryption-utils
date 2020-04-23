/***********************************************************************************
 * <pre>
 * Class: RSAEncryptionUtils.java
 * Package: com.rk.encryptionutils
 * 
 * </pre>
 * 
 * @beaninfo Description: Class with RSA Encryption/Decryption utilities 
 * 
 * @author rknechtel
 * @created Oct 8, 2012
 * 
 * <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel             Oct 8, 2012   Created
 * </pre>
 * 
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
package com.rk.encryptionutils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

public class RSAEncryptionUtils
{
  /****************************************************************************
   * <pre>
   * Recommended RSA key sizes depending on lifetime of confidential data. 
   * -------------------------------------
   * Lifetime of data       RSA key size 
   * ------------------------------------- 
   * Up to 2010             1024 bits 
   * Up to 2030             2048 bits 
   * Up to 2031 onwards     3072 bits
   * </pre>
   ****************************************************************************/
  public static int KEYSIZE_1024 = 1024;
  public static int KEYSIZE_2048 = 2048;
  public static int KEYSIZE_3072 = 3072;
  
  private static String PUBLICKEYFILE3072 = "/com/rk/encryptionutils/keys/rsapublic3072.key";
  private static String PRIVATEKEYFILE3072 = "/com/rk/encryptionutils/keys/rsaprivate3072.key";
  private static String PUBLICKEYFILE2048 = "/com/rk/encryptionutils/keys/rsapublic2048.key";
  private static String PRIVATEKEYFIL2048 = "/com/rk/encryptionutils/keys/rsaprivate2048.key";
  private static String PUBLICKEYFILE1024 = "/com/rk/encryptionutils/keys/rsapublic1024.key";
  private static String PRIVATEKEYFILE1024 = "/com/rk/encryptionutils/keys/rsaprivate1024.key";

  public RSAEncryptionUtils()
  {
  }

  /***********************************************************
   * <pre>
   * Method: main()
   * Description: This is used for Command Line usage
   * </pre>
   * 
   * @param (String[]) args
   **********************************************************/
  public static void main(String[] args)
  {
    String usage = "Usage:\n For Encryption: java com.rk.encryptionutils.RSAEncryptionUtils encrypt mystringtoencrypt 1024\n For Decryption: java com.rk.encryptionutils.RSAEncryptionUtils decrypt mystringtodecrypt 1024\n";
    RSAEncryptionUtils encryptionUtils = new RSAEncryptionUtils();

    if (args != null && args.length > 0 && args.length == 3)
    {
      String toDo = args[0];
      String text = args[1];
      int keySize = new Integer(args[2]).intValue();

      if (toDo != null && toDo.trim().equalsIgnoreCase("encrypt"))
      {
        String encryptedText = encryptionUtils.encryptRSA(text, keySize);
        System.out.println("The Encrypted value of " + text + " is: " + encryptedText);
      }
      else if (toDo != null && toDo.trim().equalsIgnoreCase("decrypt"))
      {
        String decryptedText = encryptionUtils.decryptRSA(text, keySize);
        System.out.println("The Decrypted value of " + text + " is: " + decryptedText);
      }
      else
      {
        System.out.println(usage);
      }

      // Clean Up
      encryptionUtils = null;
      toDo = null;
      text = null;
    }
    else
    {
      System.out.println(usage);
    }

  } // End of main()  
  
  /**************************************************************
   * <pre>
   * Method: createKeys()
   * Description: Create RSA Public and Private Keys using
   *              passed in Key Size and path/file name of 
   *              each key.
   * </pre>
   * 
   * @param (int) pKeySize
   * @param (String) pPrivate
   * @param (String) pPublicKey
   **************************************************************/
  public void createKeys(int pKeySize, String pPrivate, String pPublicKey)
  {
    try
    {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(pKeySize);
      KeyPair kp = kpg.genKeyPair();
      PublicKey publicKey = kp.getPublic();
      PrivateKey privateKey = kp.getPrivate();

      FileOutputStream fos1 = new FileOutputStream(pPublicKey);
      ObjectOutputStream oos1 = new ObjectOutputStream(fos1);
      oos1.writeObject(publicKey);

      FileOutputStream fos2 = new FileOutputStream(pPrivate);
      ObjectOutputStream oos2 = new ObjectOutputStream(fos2);
      oos2.writeObject(privateKey);
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: createKeys() = Error = " + e.getMessage());
    }
  } // End of createKeys()

  /****************************************************
   * <pre>
   * Method: readPublicKeyFromFile()
   * Description: Reads the RSA Public Key file.
   * </pre>
   * 
   * @param (String) pFileName
   * @return (PublicKey)
   * @throws IOException
   ****************************************************/
  private PublicKey getPublicKeyFromFile(String pFileName) throws IOException
  {
    ObjectInputStream ois = null;
    PublicKey publicKey = null;
    try
    {
      ois = new ObjectInputStream(getClass().getResourceAsStream(pFileName));
      BigInteger pubModulus = (BigInteger) ois.readObject();
      BigInteger pubExponent = (BigInteger) ois.readObject();
      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(pubModulus, pubExponent);
      KeyFactory keyFact = KeyFactory.getInstance("RSA");
      publicKey = keyFact.generatePublic(keySpec);
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: getPublicKeyFromFile() = Error = " + e.getMessage());
    }
    finally
    {
      // oin.close();
      ois.close();
    }
    return publicKey;
  } // End of readPublicKeyFromFile()

  /****************************************************
   * <pre>
   * Method: readPrivateKeyFromFile()
   * Description: Reads the RSA Private Key file.
   * </pre>
   * 
   * @param (String) pFileName
   * @return (PrivateKey)
   * @throws IOException
   ****************************************************/
  private PrivateKey getPrivateKeyFromFile(String pFileName) throws IOException
  {
    ObjectInputStream ois = null;
    PrivateKey privateKey = null;
    try
    {
      ois = new ObjectInputStream(getClass().getResourceAsStream(pFileName));
      BigInteger privModulus = (BigInteger) ois.readObject();
      BigInteger privExponent = (BigInteger) ois.readObject();
      RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(privModulus, privExponent);
      KeyFactory keyFact = KeyFactory.getInstance("RSA");
      privateKey = keyFact.generatePrivate(keySpec);
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: getPrivateKeyFromFile() = Error = " + e.getMessage());
    }
    finally
    {
      // oin.close();
      ois.close();
    }
    return privateKey;
  } // End of readPrivateKeyFromFile()

  /********************************************************
   * <pre>
   * Method: encryptRSA()
   * Description: Encrypt a String using RSA Encryption
   * </pre>
   * @param (String) pToEncrypt
   * @param (int) pKeySize
   * @return (String)
   ********************************************************/
  public String encryptRSA(String pToEncrypt, int pKeySize)
  {
    String encryptedString = "";
    String publicKeyFile = "";
    try
    {
      switch(pKeySize)
      {
        case 1024:
        {
          publicKeyFile = PUBLICKEYFILE1024;
          break;
        }
        case 2048:
        {
          publicKeyFile = PUBLICKEYFILE2048;
          break;
        }
        case 3072:
        {
          publicKeyFile = PUBLICKEYFILE3072;
          break;
        }        
      }
      
      byte[] ecnryptBytes = pToEncrypt.getBytes();
      PublicKey pubKey = getPublicKeyFromFile(publicKeyFile);
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, pubKey);
      byte[] cipherData = cipher.doFinal(ecnryptBytes);
      encryptedString = cipherData.toString();
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: encryptRSA() = Error = " + e.getMessage());
    }
    return encryptedString;
  } // End of encryptRSA()  
  
  /********************************************************
   * <pre>
   * Method: encryptRSA()
   * Description: Encrypt a String using RSA Encryption
   * </pre>
   * @param (String) pToEncrypt
   * @param (String) pPublicKey
   * @return (String)
   ********************************************************/
  public String encryptRSA(String pToEncrypt, String pPublicKey)
  {
    String encryptedString = "";
    try
    {
      byte[] ecnryptBytes = pToEncrypt.getBytes();
      PublicKey pubKey = getPublicKeyFromFile(pPublicKey);
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, pubKey);
      byte[] cipherData = cipher.doFinal(ecnryptBytes);
      encryptedString = cipherData.toString();
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: encryptRSA() = Error = " + e.getMessage());
    }
    return encryptedString;
  } // End of encryptRSA()

  /********************************************************
   * <pre>
   * Method: decryptRSA()
   * Description: Decrypt a String using RSA Encryption
   * </pre>
   * @param (String) pToDecrypt
   *  @param (int) pKeySize
   * @return (String)
   ********************************************************/
  public String decryptRSA(String pToDecrypt, int pKeySize)
  {
    String decryptedString = "";
    String publicKeyFile = "";
    try
    {
      switch(pKeySize)
      {
        case 1024:
        {
          publicKeyFile = PUBLICKEYFILE1024;
          break;
        }
        case 2048:
        {
          publicKeyFile = PUBLICKEYFILE2048;
          break;
        }
        case 3072:
        {
          publicKeyFile = PUBLICKEYFILE3072;
          break;
        }        
      }
      
      byte[] decryptBytes = pToDecrypt.getBytes();
      PrivateKey privKey = getPrivateKeyFromFile(publicKeyFile);
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.DECRYPT_MODE, privKey);
      byte[] cipherData = cipher.doFinal(decryptBytes);
      decryptedString = cipherData.toString();
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: decryptRSA() = Error = " + e.getMessage());
    }
    return decryptedString;
  } // End of decryptRSA()    
  
  /********************************************************
   * <pre>
   * Method: decryptRSA()
   * Description: Decrypt a String using RSA Encryption
   * </pre>
   * @param (String) pToDecrypt
   * @param (String) pPrivateKey
   * @return (String)
   ********************************************************/
  public String decryptRSA(String pToDecrypt, String pPrivateKey)
  {
    String decryptedString = "";
    try
    {
      byte[] decryptBytes = pToDecrypt.getBytes();
      PrivateKey privKey = getPrivateKeyFromFile(pPrivateKey);
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.DECRYPT_MODE, privKey);
      byte[] cipherData = cipher.doFinal(decryptBytes);
      decryptedString = cipherData.toString();
    }
    catch (Exception e)
    {
      System.out.println("RSAEncryptionUtils: decryptRSA() = Error = " + e.getMessage());
    }
    return decryptedString;
  } // End of decryptRSA()    
  
} // End of Class RSAEncryptionUtils
