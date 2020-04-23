/***********************************************************************************
 * <pre>
 * Class: BlowfishEncryptionUtils.java
 * Package: com.rk.encryptionutils
 * 
 * </pre>
 * 
 * @beaninfo Description: This class handles Blowfish Encryption/Decryption
 * 
 * @author rknechtel
 * @created Dec 9, 2012
 * 
 *          <pre>
 *  Mutation/Modification Log
 *  
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel             Dec 9, 2012   Created
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

public class BlowfishEncryptionUtils
{
  private static String BLOWFISHKEYFILE = "/com/rk/encryptionutils/keys/BlowfishKey.ser";
  private static String DEFAULTGENPATH = "C:\\Temp\\BlowfishKey.ser";
  private static String usage = "Usage:\n For Encryption: java com.rk.encryptionutils.BlowfishEncryptionUtils encrypt mystringtoencrypt\n For Decryption: java com.rk.encryptionutils.BlowfishEncryptionUtils decrypt mystringtodecrypt\n For Key Generation: java com.rk.encryptionutils.BlowfishEncryptionUtils genkey\n";

  public BlowfishEncryptionUtils()
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
    BlowfishEncryptionUtils encryptionUtils = new BlowfishEncryptionUtils();

    if (args != null && args.length > 0 && args.length == 1)
    {
      String toDo = args[0];
      if (toDo != null && toDo.trim().equalsIgnoreCase("genkey"))
      {
        encryptionUtils.GererateWriteBlowfishKeyFile(DEFAULTGENPATH);
      }

    }
    else if (args != null && args.length > 0 && args.length == 2)
    {
      String toDo = args[0];
      String text = args[1];
      // String keyfile = args[2]; // use for a passed in path/keyfile name

      if (toDo != null && toDo.trim().equalsIgnoreCase("encrypt"))
      {
        String encryptedText = encryptionUtils.encyptString(text);
        System.out.println("The Encrypted value of " + text + " is: " + encryptedText);
      }
      else if (toDo != null && toDo.trim().equalsIgnoreCase("decrypt"))
      {
        String decryptedText = encryptionUtils.decryptString(text);
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

  }

  /******************************************************************
   * <pre>
   * Method: encyptString()
   * Description: This method will encrypt a string using
   * </pre>
   * 
   * @param (String) pStringToEncrypt
   * @return (String)
   * @throws Exception
   ******************************************************************/
  public String encyptString(String pStringToEncrypt)
  {
    SecretKey key = null;
    String encryptedString = null;
    try
    {
      // Read in a Blowfish Key from package
      key = loadSecurityKey(BLOWFISHKEYFILE);

      // Get a Cipher
      Cipher cipher = getCipher();

      // Encrypt:
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] encrypted = cipher.doFinal(pStringToEncrypt.getBytes());
      encryptedString = bytesToString(encrypted);

      // System.out.println("BlowfishEncryptionUtils: encyptString() - " + new String(encrypted) + " " + encryptedString + " " + Arrays.toString(encrypted));

    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtils: encyptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return encryptedString;
  } // End of encyptString()

  /******************************************************************
   * <pre>
   * Method: encyptString()
   * Description: This method will encrypt a string using 
   *              Blowfish encryption
   *              pKeyToUse = 
   *              Example: C:\temp\MyBlowfishSecretKey.ser
   * </pre>
   * 
   * @param (String) pKeyToUse
   * @param (String) pStringToEncrypt
   * @return (String)
   * @throws Exception
   ******************************************************************/
  public String encyptString(String pKeyToUse, String pStringToEncrypt)
  {
    SecretKey key = null;
    String encryptedString = null;
    try
    {
      // Read in a Blowfish Key
      key = getKeyFile(pKeyToUse);

      // Get a Cipher
      Cipher cipher = getCipher();

      // Encrypt:
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] encrypted = cipher.doFinal(pStringToEncrypt.getBytes());
      encryptedString = bytesToString(encrypted);

      // System.out.println("BlowfishEncryptionUtils: encyptString() - " + new String(encrypted) + " " + encryptedString + " " + Arrays.toString(encrypted));

    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtils: encyptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return encryptedString;
  } // End of encyptString()

  /******************************************************************
   * <pre>
   * Method: decryptString()
   * Description: This method will decrypt a string using 
   *              Blowfish decryption
   *              pKeyToUse = 
   *              Example: C:\temp\MyBlowfishSecretKey.ser
   * </pre>
   * 
   * @param (String) pStringToDecrypt
   * @return (String)
   * @throws Exception
   ******************************************************************/
  public String decryptString(String pStringToDecrypt)
  {
    SecretKey key = null;
    String decryptedString = null;

    try
    {
      // Read in a Blowfish Key from package
      key = loadSecurityKey(BLOWFISHKEYFILE);

      // Get a Cipher
      Cipher cipher = getCipher();

      // Decrypt:
      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] decrypted = cipher.doFinal(stringToBytes(pStringToDecrypt));
      decryptedString = new String(decrypted);

      // System.out.println("BlowfishEncryptionUtils: decryptString() - " + decryptedString + " " + Arrays.toString(decrypted));

    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtils: decryptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return decryptedString;
  } // End of decryptString()

  /******************************************************************
   * <pre>
   * Method: decryptString()
   * Description: This method will decrypt a string using 
   *              Blowfish decryption
   *              pKeyToUse = 
   *              Example: C:\temp\MyBlowfishSecretKey.ser
   * </pre>
   * 
   * @param (String) pKeyToUse
   * @param (String) pStringToDecrypt
   * @return (String)
   * @throws Exception
   ******************************************************************/
  public String decryptString(String pKeyToUse, String pStringToDecrypt)
  {
    SecretKey key = null;
    String decryptedString = null;

    try
    {
      // Read in a Blowfish Key
      key = getKeyFile(pKeyToUse);

      // Get a Cipher
      Cipher cipher = getCipher();

      // Decrypt:
      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] decrypted = cipher.doFinal(stringToBytes(pStringToDecrypt));
      decryptedString = new String(decrypted);

      // System.out.println("BlowfishEncryptionUtils: decryptString() - " + decryptedString + " " + Arrays.toString(decrypted));

    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtils: decryptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return decryptedString;
  } // End of decryptString()

  /*******************************************************************
   * <pre>
   * Method: GererateWriteBlowfishKeyFile()
   * Description: This method will generate a Blowfish key
   *              and write it out to where the input parameter
   *              says to.
   *              pWhereToWRite =
   *              Example: C:\Temp\BlowfishKey.ser
   * </pre>
   * 
   * @param pWhereToWrite
   *******************************************************************/
  public void GererateWriteBlowfishKeyFile(String pWhereToWrite)
  {
    if (pWhereToWrite == null)
    {
      pWhereToWrite = "C:\\Temp\\BlowfishKey.ser";
    }

    SecretKey key = generateSecretKey();
    writeKey(pWhereToWrite, key);
  } // End of GererateWriteBlowfishKeyFile()

  /****************************************************************
   * <pre>
   * Method: generateSecretKey()
   * Description: This will generate a Blowfish secret key
   *               Example:
   *               SecretKey key = generateSecretKey();
   * </pre>
   * 
   * @return (SecretKey)
   ****************************************************************/
  private SecretKey generateSecretKey()
  {
    KeyGenerator keygenerator;
    SecretKey secretkey = null;
    try
    {
      keygenerator = KeyGenerator.getInstance("Blowfish");
      secretkey = keygenerator.generateKey();
    }
    catch (NoSuchAlgorithmException e)
    {
      e.printStackTrace();
    }

    return secretkey;
  } // End of generateSecretKey()

  /***************************************************************
   * <pre>
   * Method: writeKey()
   * Description: This will write out the Blowfish secret key
   *               pKeyToWRite =
   *               Example: C:\temp\MyBlowfishSecretKey.ser
   * </pre>
   * 
   * @param (String) pKeyToWRite
   * @param (SecretKey) pMyKey
   ***************************************************************/
  private void writeKey(String pKeyToWRite, SecretKey pMyKey)
  {
    ObjectOutputStream keyFileOut = null;
    try
    {
      keyFileOut = new ObjectOutputStream(new FileOutputStream(pKeyToWRite));
      keyFileOut.writeObject(pMyKey);
      keyFileOut.close();
    }
    catch (IOException e)
    {
      e.printStackTrace();
    }
  } // End of writeKey()

  /*********************************************************
   * <pre>
   * Method: getKeyFile()
   * Description: This will get a Blowfish secret key
   *              pKeyToRead = 
   *              Example: C:\temp\MyBlowfishSecretKey.ser
   * </pre>
   * 
   * @param (String) pKeyToRead
   * @return SecretKey
   *********************************************************/
  private SecretKey getKeyFile(String pKeyToRead)
  {
    SecretKey key = null;
    ObjectInputStream keyFile;
    try
    {
      keyFile = new ObjectInputStream(new FileInputStream(pKeyToRead));
      key = (SecretKey) keyFile.readObject();
      keyFile.close();
    }
    catch (FileNotFoundException ffne)
    {
      ffne.printStackTrace();
    }
    catch (IOException ioe)
    {
      ioe.printStackTrace();
    }
    catch (ClassNotFoundException cnfe)
    {
      cnfe.printStackTrace();
    }
    return key;

  } // End of getKeyFile()

  /***********************************************************************
   * <pre>
   * Method: loadSecurityKey()
   * Description: Loads the Security Key
   *              Must be from a Java Package.
   *              Example: /com/myproject/keys/MyBlowfishSecretKey.ser
   * </pre>
   * 
   * @param (String) pFileName
   * @return (SecretKey)
   * @throws Exception
   *********************************************************************/
  public SecretKey loadSecurityKey(String pFileName) throws Exception
  {
    SecretKey key = null;
    try
    {
      ObjectInputStream ois = new ObjectInputStream(getClass().getResourceAsStream(pFileName));
      key = (SecretKey) ois.readObject();
      ois.close();
    }
    catch (Exception e)
    {
      String msg = "BlowfishEncryptionUtils: loadSecurityKey() - Error = " + e.getMessage();
      System.out.println(msg);
      e.printStackTrace();
      throw new Exception(msg);
    }
    return key;
  } // End of loadSecurityKey()

  /*******************************************************
   * <pre>
   * Method: getCipher()
   * Description: This will get a Cipher from a passed 
   *              in Blowfish SecretKey
   * </pre>
   * 
   * @return (Cipher)
   *******************************************************/
  private Cipher getCipher()
  {
    Cipher cipher = null;
    try
    {
      cipher = Cipher.getInstance("Blowfish"); // Optional: Cipher.getInstance("Blowfish/ECB/PKCS5Padding")
    }
    catch (NoSuchAlgorithmException e)
    {
      e.printStackTrace();
    }
    catch (NoSuchPaddingException e)
    {
      e.printStackTrace();
    }
    return cipher;
  } // End of getCipher()

  /*************************************************
   * <pre>
   * Method: stringToBytes()
   * Description: Convert a sString to Bytes
   * </pre>
   * 
   * @param (String) pPlainText
   * @return byte[]
   *************************************************/
  private byte[] stringToBytes(String pPlainText)
  {
    byte[] rawText = Base64.decodeBase64(pPlainText);
    return rawText;
  } // End of stringToBytes()

  /*************************************************************
   * <pre>
   * Method: bytesToString()
   * Description: This method will convert bytes to a String
   * </pre>
   * @param byte[] pRawText
   * @return String
   *************************************************************/
  private String bytesToString(byte[] pRawText)
  {
    String plainText = null;
    byte[] encodedBytes = Base64.encodeBase64(pRawText);
    plainText = new String(encodedBytes);
    
    return plainText;
  } // End of bytesToString()

} // End of Class BlowfishEncryptionUtils
