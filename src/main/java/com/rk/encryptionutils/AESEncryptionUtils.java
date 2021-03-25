/***********************************************************************************
 * <pre>
 * Class: AESEncryptionUtils.java
 * Package: com.rk.encryptionutils
 * 
 * </pre>
 * 
 * @beaninfo Description: Class with a collection of AES utilities
 * 
 * @author rknechtel
 * @created Sep 28, 2012
 * 
 *  <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel              Sep 28, 2012        Created
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
package com.rk.encryptionutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.rk.encryptionutils.utils.FileResourcesUtils;

import com.rk.encryptionutils.thirdparty.StringEncrypter;

public class AESEncryptionUtils
{
  // Note: To do the AES 193 and 256 encryption requires the unlimited encryption policy files in $JRE_HOME/lib/security
  // Ref: http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
  // Note: jars also in project under "securitypolicy" directory
  private static String KEYFILE256 = "/com/rk/encryptionutils/keys/aes256.key";
  private static String KEYFILE192 = "/com/rk/encryptionutils/keys/aes192.key";
  private static String KEYFILE128 = "/com/rk/encryptionutils/keys/aes128.key";

  public AESEncryptionUtils()
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
    String usage = "Usage:\n For Encryption: java com.rk.encryptionutils.AESEncryptionUtils encrypt mystringtoencrypt\n For Decryption: java com.rk.encryptionutils.AESEncryptionUtils decrypt mystringtodecrypt\n";
    AESEncryptionUtils encryptionUtils = new AESEncryptionUtils();

    if (args != null && args.length > 0 && args.length == 2)
    {
      String toDo = args[0];
      String text = args[1];

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

  } // End of main()

  /************************************************************
   * <pre>
   * Method: encyptString()
   * Description: Will encrypt a passed in String using AES
   * </pre>
   * 
   * @param (String) pValue
   * @return (String)
   ***********************************************************/
  public String encyptString(String pValue)
  {
    String encryptedValue = null;
    SecretKey aesKey = null;

    try
    {
      // File aesKeyFile = new File(getAESKeyFile());
      // aesKey = loadAESKey(aesKeyFile);
      // aesKey = loadAESKey(getAESKeyFile());
      // aesKey = loadSecurityKey(KEYFILE256);
      // aesKey = loadSecurityKey(KEYFILE192);
      aesKey = loadSecurityKey(KEYFILE128);
      StringEncrypter aesEncrypt = new StringEncrypter(aesKey, aesKey.getAlgorithm());
      encryptedValue = aesEncrypt.encrypt(pValue);
    }
    catch (IOException ioe)
    {
      System.out.println("AESEncryptionUtils: encyptString() IOException - Error = " + ioe.getMessage());
      ioe.printStackTrace();
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtils: encyptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return encryptedValue;
  } // End of encyptString()

  /************************************************************
   * <pre>
   * Method: encyptString()
   * Description: Will encrypt a passed in String using 
   *              a passed in AES key file.
   *              Example: myKeyFile.key
   * </pre>
   * 
   * @param (SecretKey) pKey
   * @param (String) pValue
   * @return (String)
   ***********************************************************/
  public String encyptString(SecretKey pKey, String pValue)
  {
    String encryptedValue = null;

    try
    {
      StringEncrypter aesEncrypt = new StringEncrypter(pKey, pKey.getAlgorithm());
      encryptedValue = aesEncrypt.encrypt(pValue);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtils: encyptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return encryptedValue;
  } // End of encyptString()


  /************************************************************
   * <pre>
   * Method: encyptString()
   * Description: Will encrypt a passed in String using 
   *              a passed in path to an AES key file.
   *              Example: C:\temp\myKeyFile.key
   * </pre>
   * 
   * @param (String) pKeyPath
   * @param (String) pValue
   * @return (String)
   ***********************************************************/
  public String encyptString(String pKeyPath, String pValue)
  {
    String encryptedValue = null;

    try
    {
      SecretKey key = loadAESKey(pKeyPath);
      StringEncrypter aesEncrypt = new StringEncrypter(key, key.getAlgorithm());
      encryptedValue = aesEncrypt.encrypt(pValue);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtils: encyptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return encryptedValue;
  } // End of encyptString()

      /***************************************************************************************************
     * <pre>
     * Method: encyptStringWithKey()
     * Description: Will return an encrypted a string with a passed in keyfile (path and filename).
     * </pre>
     * 
     * @param (String) pValue
     * @param (String) pKeyFile
     * @return (String)
     **************************************************************************************************/
    public String encyptStringWithKey(String pValue, String pKeyFile)
    {
        String encryptedValue = null;
        SecretKey aesKey = null;

        try
        {
            aesKey = loadAESKey(pKeyFile);
            if(aesKey != null)
            {
              StringEncrypter aesEncrypt = new StringEncrypter(aesKey, aesKey.getAlgorithm());
              encryptedValue = aesEncrypt.encrypt(pValue);
            }
        }
        catch(IOException ioe)
        {
            System.out.println("AESEncryptionUtils: encyptStringWithKey() IOException - Error = " + ioe.getMessage());
            ioe.printStackTrace();
        }
        catch(Exception e)
        {
            System.out.println("AESEncryptionUtils: encyptStringWithKey() Exception - Error = " + e.getMessage());
            e.printStackTrace();
        }

        return encryptedValue;
      } // End of encyptStringWithKey()

  /*****************************************************
   * <pre>
   * Method: decryptString()
   * Description: Decrypt's and AES encrypted String
   * </pre>
   * 
   * @param (String) pEncryptedString
   * @return (String)
   ****************************************************/
  public String decryptString(String pEncryptedString)
  {
    String decryptedString = null;
    SecretKey aesKey = null;

    try
    {
      // File aesKeyFile = new File(KEYFILE);
      // aesKey = loadAESKey(aesKeyFile);
      // aesKey = loadSecurityKey(KEYFILE256);
      // aesKey = loadSecurityKey(KEYFILE192);
      aesKey = loadSecurityKey(KEYFILE128);
      StringEncrypter aesEncrypt = new StringEncrypter(aesKey, aesKey.getAlgorithm());
      decryptedString = aesEncrypt.decrypt(pEncryptedString);
    }
    catch (IOException ioe)
    {
      System.out.println("AESEncryptionUtils: decryptString() IOException - Error = " + ioe.getMessage());
      ioe.printStackTrace();
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtils: decryptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return decryptedString;
  } // End of decryptString()

  /*******************************************************
   * <pre>
   * Method: decryptString()
   * Description: Decrypt's and AES encrypted String
   *              using a passed in AES key file.
   *              Example: myKeyFile.key
   * </pre>
   * 
   * @param (SecretKey) pKey
   * @param (String) pEncryptedString
   * @return (String)
   ******************************************************/
  public String decryptString(SecretKey pKey, String pEncryptedString)
  {
    String decryptedString = null;

    try
    {
      StringEncrypter aesEncrypt = new StringEncrypter(pKey, pKey.getAlgorithm());
      decryptedString = aesEncrypt.decrypt(pEncryptedString);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtils: decryptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return decryptedString;
  } // End of decryptString()

  /***********************************************************
   * <pre>
   * Method: decryptString()
   * Description: Decrypt's and AES encrypted String
   *              using a passed in path to an AES key file.
   *              Example: C:\temp\myKeyFile.key
   * </pre>
   * 
   * @param (String) pKeyPath
   * @param (String) pEncryptedString
   * @return (String)
   **********************************************************/
  public String decryptString(String pKeyPath, String pEncryptedString)
  {
    String decryptedString = null;

    try
    {
      SecretKey key = loadAESKey(pKeyPath);
      StringEncrypter aesEncrypt = new StringEncrypter(key, key.getAlgorithm());
      decryptedString = aesEncrypt.decrypt(pEncryptedString);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtils: decryptString() Exception - Error = " + e.getMessage());
      e.printStackTrace();
    }

    return decryptedString;
  } // End of decryptString()

      /***********************************************************************************************
     * <pre>
     * Method: decryptStringWithKey()
     * Description: This will decrpyt a string with a passed in keyfile (path and filename).
     * </pre>
     * 
     * @param (String) pEncryptedString
     * @param (String) pKeyFile
     * @return (String)
     ***********************************************************************************************/
    public String decryptStringWithKey(String pEncryptedString, String pKeyFile)
    {
        String decryptedString = null;
        SecretKey aesKey = null;

        try
        {
            aesKey = loadAESKey(pKeyFile);
            if(aesKey != null)
            {
              StringEncrypter aesEncrypt = new StringEncrypter(aesKey, aesKey.getAlgorithm());
              decryptedString = aesEncrypt.decrypt(pEncryptedString);
            }
        }
        catch(IOException ioe)
        {
            System.out.println("AESEncryptionUtils: decryptStringWithKey() IOException - Error = " + ioe.getMessage());
            ioe.printStackTrace();
        }
        catch(Exception e)
        {
            System.out.println("AESEncryptionUtils: decryptStringWithKey() Exception - Error = " + e.getMessage());
            e.printStackTrace();
        }

        return decryptedString;
      } // End of decryptStringWithKey()
  
  /*************************************************************
   * <pre>
   * Method: loadSecurityKey()
   * Description: Loads the Security Key
   *              Must be from a Java Package.
   *              Example: /com/myproject/keys/myaeskey.key
   * </pre>
   * 
   * @param (String) pFileName
   * @return (SecretKey)
   * @throws Exception
   ************************************************************/
  public SecretKey loadSecurityKey(String pFileName) throws Exception
  {
    SecretKey key = null;
    String sKey = null;
    try
    {
      ObjectInputStream ois = new ObjectInputStream(getClass().getResourceAsStream(pFileName));
      sKey = (String) ois.readObject();
      ois.close();

      byte[] encoded = new BigInteger(sKey, 16).toByteArray();
      key = new SecretKeySpec(encoded, "AES");
    }
    catch (Exception e)
    {
      String msg = "AESEncryptionUtils: loadSecurityKey() - Error = " + e.getMessage();
      System.out.println(msg);
      e.printStackTrace();
      throw new Exception(msg);
    }
    return key;
  } // End of loadSecurityKey()

  /******************************************************************
   * <pre>
   * Method: loadAESKey()
   * Description: Will load an AES key file from the filesystem
   *              Example: C:\temp\myKeyFile.key
   * </pre>
   * 
   * @param (String) pFile
   * @return (SecretKey)
   * @throws Exception
   ****************************************************************/
  public SecretKey loadAESKey(String pFile) throws Exception
  {
    SecretKey key = null;
    String sKey = null;
    FileResourcesUtils fru = new FileResourcesUtils();
    try
    {
        InputStream keyIS = fru.getFileFromResourceAsStream(pFile);
        //InputStream keyIS = new FileInputStream(pFile);
        ObjectInputStream ois = new ObjectInputStream(keyIS);
        sKey = (String) ois.readObject();
        ois.close();
        //keyIS.close();
        byte[] encoded = new BigInteger(sKey, 16).toByteArray();
        key = new SecretKeySpec(encoded, "AES");
    }
    catch(Exception e)
    {
        String msg = "AESEncryptionUtils: loadAESKey() - Error = " + e.getMessage();
        System.out.println(msg);
        e.printStackTrace();
        throw new Exception(msg);
    }

    return key;

  } // End of loadAESKey()

  /************************************************************
   * <pre>
   * Method: createAESKeyFile()
   * Description: Creates an AES Key File
   * </pre>
   * 
   * @param (String) pKeyFileName Full file path and filename 
   *                              Example: C:\temp\myKeyFile.key
   * @param (int) pKeySize Possible values: 128, 192, 256
   * @return (boolean)
   **********************************************************/
  public boolean createAESKeyFile(String pKeyFileName, int pKeySize) throws Exception
  {
    boolean keyCreated = false;
    if (pKeyFileName != null)
    {
      File newFile = new File(pKeyFileName);
      try
      {
        SecretKey key = generateAESKey(pKeySize);
        saveAESKey(key, newFile);
        keyCreated = true;
      }
      catch (NoSuchAlgorithmException nsae)
      {
        System.out.println("AESEncryptionUtils: createAESKeyFile() NoSuchAlgorithmException - Error = " + nsae.getMessage());
        nsae.printStackTrace();
      }
      catch (IOException ioe)
      {
        System.out.println("AESEncryptionUtils: createAESKeyFile() IOException - Error = " + ioe.getMessage());
        ioe.printStackTrace();
      }
      catch (Exception e)
      {
        System.out.println("AESEncryptionUtils: createAESKeyFile() sError = " + e.getMessage());
        e.printStackTrace();
      }
    }
    return keyCreated;
  } // End of createAESKeyFile()

  /**************************************************
   * <pre>
   * Method: generateAESKey()
   * Description: Will generate an 256 AES key
   * </pre>
   * 
   * @param (int) pKeySize Possible values: 128, 192, 256
   * 
   * @return (SecretKey)
   * @throws NoSuchAlgorithmException
   *************************************************/
  private SecretKey generateAESKey(int pKeySize) throws NoSuchAlgorithmException, Exception
  {
    SecretKey key = null;
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    if (pKeySize == 128 || pKeySize == 192 || pKeySize == 256)
    {
      keyGenerator.init(pKeySize); // 128 default;
      // 192 and 256 also possible - using 192 and 256 requires unlimited encryption policy jars in $JRE_HOME/lib/security
      key = keyGenerator.generateKey();
    }
    else
    {
      throw new Exception("Invalid Key Size - must be 128, 192 or 256 - using 192 and 256 requires unlimited encryption policy jars in $JRE_HOME/lib/security");
    }

    return key;
  } // End of generateAESKey()

  /******************************************************************
   * <pre>
   * Method: saveAESKey()
   * Description: Will save an AES encryption key to filesystem
   * </pre>
   * 
   * @param (SecretKey) pKey
   * @param (File) pFile
   * @throws IOException
   ******************************************************************/
  private void saveAESKey(SecretKey pKey, File pFile) throws IOException, FileNotFoundException
  {
    byte[] encoded = pKey.getEncoded();
    String data = new BigInteger(1, encoded).toString(16);
    // writeStringToFile(pFile, data);
    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(pFile, false));
    out.writeObject(data);
    out.flush();
    out.close();

  } // End of saveAESKey()

} // End of Class AESEncryptionUtils
