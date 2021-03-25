package com.rk.encryptionutils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class AESEncryptionUtilsTest
{
  private static String KEYFILE128 = "com/rk/encryptionutils/keys/aes128.key";
  private static String KEYFILE192 = "com/rk/encryptionutils/keys/aes192.key";
  private static String KEYFILE256 = "com/rk/encryptionutils/keys/aes256.key";
  private static String TESTKEYFILE128 = "target/aes128.key";
  private static String TESTKEYFILE192 = "target/aes192.key";
  private static String TESTKEYFILE256 = "target/aes256.key";
  private static String TESTUNENCRYPTEDPW = "testpw";
  private static String TESTENCRYPTED128PW = "JNaxjdhahuWahZHPY/mOPw==";
  private static String TESTENCRYPTED192PW = "QkXha6O8Y6SW3lKXqcJFdA==";
  private static String TESTENCRYPTED256PW = "/sN86TsXEZQNBCdEaaHU1w==";

  
  @Test
  public void createKeyFile128Test()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    boolean created = false;
    
    try
    {
      created = encryptUtils.createAESKeyFile(TESTKEYFILE128, 128);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: createKeyFile128Test() Error = " + e.getMessage());
    }

    assertEquals(true, created);
   
  } // End of Test createKeyFile128Test()


  @Test
  public void createKeyFile192Test()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    boolean created = false;
    
    try
    {
      created = encryptUtils.createAESKeyFile(TESTKEYFILE192, 192);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: createKeyFile192Test() Error = " + e.getMessage());
    }

    assertEquals(true, created);

  } // End of Test createKeyFile192Test()

  @Test
  public void createKeyFile256Test()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    boolean created = false;
    
    try
    {
      created = encryptUtils.createAESKeyFile(TESTKEYFILE256, 256);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: createKeyFile256Test() Error = " + e.getMessage());
    }

    assertEquals(true, created);
    
  } // End of Test createKeyFile256Test()

  @Test
  public void encrypt128StringTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String encryptedString128 = null;
    try
    {
      encryptedString128 = encryptUtils.encyptString(TESTUNENCRYPTEDPW);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encrypt128StringTest() Error = " + e.getMessage());
    }
    
    if(encryptedString128 != null)
    {
      assertEquals(TESTENCRYPTED128PW, encryptedString128);
    }
    else 
    {
      assert(false);
    }
    
  } // End of Test encryptStringTest()
  
  @Test
  public void encrypt128StringWithKeyTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String encryptedString128 = null;
    try
    {
      encryptedString128 = encryptUtils.encyptStringWithKey(TESTUNENCRYPTEDPW, KEYFILE128);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encrypt128StringWithKeyTest() Error = " + e.getMessage());
    }
    
    // Clean up
    encryptUtils = null;

    if(encryptedString128 != null)
    {
      assertEquals(TESTENCRYPTED128PW, encryptedString128);
    }
    else 
    {
      assert(false);
    }

  } // End of Test encrypt128StringWithKeyTest()
  
  @Test
  public void encrypt192StringWithKeyTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String encryptedString192 = null;
    try
    {
      encryptedString192 = encryptUtils.encyptStringWithKey(TESTUNENCRYPTEDPW, KEYFILE192);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encrypt192StringWithKeyTest() Error = " + e.getMessage());
    }

    // Clean up
    encryptUtils = null;

    if(encryptedString192 != null)
    {
      assertEquals(TESTENCRYPTED192PW, encryptedString192);
    }
    else 
    {
      assert(false);
    }

  } // End of Test encrypt192StringWithKeyTest()

  @Test
  public void encrypt256StringWithKeyTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String encryptedString256 = null;
    try
    {
      encryptedString256 = encryptUtils.encyptStringWithKey(TESTUNENCRYPTEDPW, KEYFILE256);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encrypt256StringWithKeyTest() Error = " + e.getMessage());
    }

    // Clean up
    encryptUtils = null;

    if(encryptedString256 != null)
    {
      assertEquals(TESTENCRYPTED256PW, encryptedString256);
    }
    else 
    {
      assert(false);
    }

  } // End of Test encrypt256StringWithKeyTest()

  @Test
  public void decrypt128StringTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String decryptedString128 = null;
    try
    {
      decryptedString128 = encryptUtils.decryptString(TESTENCRYPTED128PW);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decrypt128StringTest() Error = " + e.getMessage());
    }

    // Clean up
    encryptUtils = null;

    if(decryptedString128 != null)
    {
      assertEquals(TESTUNENCRYPTEDPW, decryptedString128);
    }
    else 
    {
      assert(false);
    }

  } // End of Test decrypt128StringTest()
  
  @Test
  public void decrypt128StringWithKeyTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String decryptedString128 = null;
    try
    {
      decryptedString128 = encryptUtils.decryptStringWithKey(TESTENCRYPTED128PW, KEYFILE128);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decrypt128StringWithKeyTest() Error = " + e.getMessage());
    }

    // Clean up
    encryptUtils = null;

    if(decryptedString128 != null)
    {
      assertEquals(TESTUNENCRYPTEDPW, decryptedString128);
    }
    else 
    {
      assert(false);
    } 

  } // End of Test decrypt128StringWithKeyTest()  

  @Test
  public void decrypt192StringWithKeyTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String decryptedString192 = null;
    try
    {
      decryptedString192 = encryptUtils.decryptStringWithKey(TESTENCRYPTED192PW, KEYFILE192);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decrypt1292tringWithKeyTest() Error = " + e.getMessage());
    }

    // Clean up
    encryptUtils = null;

    if(decryptedString192 != null)
    {
      assertEquals(TESTUNENCRYPTEDPW, decryptedString192);
    }
    else 
    {
      assert(false);
    } 

  } // End of Test decrypt192StringWithKeyTest()  

  @Test
  public void decrypt256StringWithKeyTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    String decryptedString256 = null;
    try
    {
      decryptedString256 = encryptUtils.decryptStringWithKey(TESTENCRYPTED256PW, KEYFILE256);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decrypt256StringWithKeyTest() Error = " + e.getMessage());
    }

    // Clean up
    encryptUtils = null;

    if(decryptedString256 != null)
    {
      assertEquals(TESTUNENCRYPTEDPW, decryptedString256);
    }
    else 
    {
      assert(false);
    } 

  } // End of Test decrypt256StringWithKeyTest()  

} // End of Class AESEncryptionUtilsTest