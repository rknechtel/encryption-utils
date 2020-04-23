package com.rk.encryptionutils;

import javax.crypto.SecretKey;

import org.junit.Test;


public class AESEncryptionUtilsTest
{ 
  
  // Home:
  private static String HOME_PATH="C:\\Projects_Java\\NewProjects";
  private static String FULLPATHKEYFILE256 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\aes256.key";
  private static String FULLPATHKEYFILE192 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\aes192.key";
  private static String FULLPATHKEYFILE128 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\aes128.key";

  private static String KEYFILE256 = "/com/rk/encryptionutils/keys/aes256.key";
  private static String KEYFILE192 = "/com/rk/encryptionutils/keys/aes192.key";
  private static String KEYFILE128 = "/com/rk/encryptionutils/keys/aes128.key";  
  
  @Test  
  public void createKeyFileTest()
  {
    //AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    //boolean created = false;
    
    try
    {
      //created = encryptUtils.createAESKeyFile(KEYFILE256, 256);
      //created = encryptUtils.createAESKeyFile(KEYFILE192, 192);
      //created = encryptUtils.createAESKeyFile(KEYFILE128, 128);
      //assert(created == true);
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: getKeyFileTest() Error = " + e.getMessage());
    }
   
  } // End of Test getKeyFileTest()

  @Test
  public void encryptStringTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    try
    {
      String encryptedString128 = encryptUtils.encyptString("testpw");
      assert(encryptedString128.equals("JNaxjdhahuWahZHPY/mOPw=="));
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encryptStringTest() Error = " + e.getMessage());
    }
    
  } // End of Test encryptStringTest()
  
  @Test
  public void encryptStringWithKeyTest1()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    try
    {
      SecretKey key = encryptUtils.loadSecurityKey(KEYFILE128);
      String encryptedString128 = encryptUtils.encyptString(key, "testpw");
      assert(encryptedString128.equals("JNaxjdhahuWahZHPY/mOPw=="));
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encryptStringWithKeyTest1() Error = " + e.getMessage());
    }

  } // End of Test encryptStringWithKeyTest1()
  
  @Test
  public void encryptStringWithKeyTest2()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    try
    {
      SecretKey key = encryptUtils.loadAESKey(FULLPATHKEYFILE128);
      String encryptedString128 = encryptUtils.encyptString(key, "testpw");
      assert(encryptedString128.equals("JNaxjdhahuWahZHPY/mOPw=="));
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encryptStringWithKeyTest2() Error = " + e.getMessage());
    }

  } // End of Test encryptStringWithKeyTest2()    
  
  @Test
  public void encryptStringWithKeyTest3()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    try
    {
      String encryptedString128 = encryptUtils.encyptString(FULLPATHKEYFILE128, "testpw");
      assert(encryptedString128.equals("JNaxjdhahuWahZHPY/mOPw=="));
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: encryptStringWithKeyTest3() Error = " + e.getMessage());
    }

  } // End of Test encryptStringWithKeyTest3()   
  
  @Test  
  public void decryptStringTest()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();
    try
    {
      String decryptedString128 = encryptUtils.decryptString("JNaxjdhahuWahZHPY/mOPw==");
      assert(decryptedString128.equals("testpw"));    
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decryptStringTest() Error = " + e.getMessage());
    }

  } // End of Test decryptStringTest()  
  
  @Test  
  public void decryptStringWithKeyTest1()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();

    try
    {
      SecretKey key = encryptUtils.loadSecurityKey(KEYFILE128);      
      String decryptedString128 = encryptUtils.decryptString(key, "JNaxjdhahuWahZHPY/mOPw==");
      assert(decryptedString128.equals("testpw"));      
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decryptStringWithKeyTest1() Error = " + e.getMessage());
    }

  } // End of Test decryptStringWithKeyTest1()
  
  @Test  
  public void decryptStringWithKeyTest2()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();

    try
    {
      SecretKey key = encryptUtils.loadAESKey(FULLPATHKEYFILE128);     
      String decryptedString128 = encryptUtils.decryptString(key, "JNaxjdhahuWahZHPY/mOPw==");
      assert(decryptedString128.equals("testpw"));      
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decryptStringWithKeyTest2() Error = " + e.getMessage());
    }

  } // End of Test decryptStringWithKeyTest2()  
  
  @Test  
  public void decryptStringWithKeyTest3()
  {
    AESEncryptionUtils encryptUtils = new AESEncryptionUtils();

    try
    {   
      String decryptedString128 = encryptUtils.decryptString(FULLPATHKEYFILE128, "JNaxjdhahuWahZHPY/mOPw==");
      assert(decryptedString128.equals("testpw"));      
    }
    catch (Exception e)
    {
      System.out.println("AESEncryptionUtilsTest: decryptStringWithKeyTest3() Error = " + e.getMessage());
    }

  } // End of Test decryptStringWithKeyTest3()  
  
}
