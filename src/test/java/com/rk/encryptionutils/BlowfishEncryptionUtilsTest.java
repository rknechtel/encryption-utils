package com.rk.encryptionutils;

import org.junit.Test;


public class BlowfishEncryptionUtilsTest
{

  private static String HOME_PATH="C:\\Projects_Java\\NewProjects";
  private static String FULLPATHKEYFILE = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\BlowfishKey.ser";

  @Test
  public void encryptStringTest1()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();
    try
    {
      String encryptedString = encryptUtils.encyptString("mystringtoencrypt");
      assert (encryptedString.equals("nrGYk7iMlOetp6d4xct3B4WonS5KzbXE"));
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: encryptStringTest1() Error = " + e.getMessage());
    }

  } // End of Test encryptStringTest1()

  @Test
  public void encryptStringWithKeyTest2()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();
    try
    {
      String encryptedString = encryptUtils.encyptString(FULLPATHKEYFILE, "mystringtoencrypt");
      assert (encryptedString.equals("nrGYk7iMlOetp6d4xct3B4WonS5KzbXE"));
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: encryptStringWithKeyTest2() Error = " + e.getMessage());
    }

  } // End of Test encryptStringWithKeyTest2()

  @Test
  public void decryptStringTest1()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();
    try
    {
      String decryptedString = encryptUtils.decryptString("nrGYk7iMlOetp6d4xct3B4WonS5KzbXE");
      assert (decryptedString.equals("mystringtoencrypt"));
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: decryptStringTest1() Error = " + e.getMessage());
    }

  } // End of Test decryptStringTest1()

  @Test
  public void decryptStringWithKeyTest2()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();

    try
    {
      String decryptedString = encryptUtils.decryptString(FULLPATHKEYFILE, "nrGYk7iMlOetp6d4xct3B4WonS5KzbXE");
      assert (decryptedString.equals("mystringtoencrypt"));
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: decryptStringWithKeyTest2() Error = " + e.getMessage());
    }

  } // End of Test decryptStringWithKeyTest2()

}
