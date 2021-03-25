package com.rk.encryptionutils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;


public class BlowfishEncryptionUtilsTest
{

  private static String BLOWFISHKEY = "com/rk/encryptionutils/keys//BlowfishKey.ser";
  private static String UNENCRYPTEDSTRING = "mystringtoencrypt";
  private static String ENCRYPTEDSTRING = "nrGYk7iMlOetp6d4xct3B4WonS5KzbXE";

  @Test
  public void encryptStringTest()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();
    try
    {
      String encryptedString = encryptUtils.encyptString(UNENCRYPTEDSTRING);
      assertEquals(ENCRYPTEDSTRING, encryptedString);
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: encryptStringTest() Error = " + e.getMessage());
    }

  } // End of Test encryptStringTest()

  @Test
  public void encryptStringWithKeyTest()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();
    try
    {
      String encryptedString = encryptUtils.encyptString(BLOWFISHKEY, UNENCRYPTEDSTRING);
      assertEquals(ENCRYPTEDSTRING, encryptedString);
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: encryptStringWithKeyTest() Error = " + e.getMessage());
    }

  } // End of Test encryptStringWithKeyTest()

  @Test
  public void decryptStringTest()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();
    try
    {
      String decryptedString = encryptUtils.decryptString(ENCRYPTEDSTRING);
      assert (decryptedString.equals(UNENCRYPTEDSTRING));
      assertEquals(UNENCRYPTEDSTRING, decryptedString);
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: decryptStringTest() Error = " + e.getMessage());
    }

  } // End of Test decryptStringTest()

  @Test
  public void decryptStringWithKeyTest()
  {
    BlowfishEncryptionUtils encryptUtils = new BlowfishEncryptionUtils();

    try
    {
      String decryptedString = encryptUtils.decryptString(BLOWFISHKEY, ENCRYPTEDSTRING);
      assertEquals(UNENCRYPTEDSTRING, decryptedString);
    }
    catch (Exception e)
    {
      System.out.println("BlowfishEncryptionUtilsTest: decryptStringWithKeyTest() Error = " + e.getMessage());
    }

  } // End of Test decryptStringWithKeyTest()

} // End of Class BlowfishEncryptionUtilsTest
