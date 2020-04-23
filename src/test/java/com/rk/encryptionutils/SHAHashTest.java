package com.rk.encryptionutils;

import org.junit.Assert;
import org.junit.Test;


public class SHAHashTest
{

  private static final String TESTTEXT = "This is a test of SHA-1 Hashing.";

  @Test
  public void TestSHAHashing()
  {
    TestSHA1();
    TestSHA256();
    TestSHA384();
    TestSHA512();
  }
  
  public void TestSHA1()
  {
    SHAHashing hashme = new SHAHashing();
    try
    {
      String hashedText = hashme.SHAHash(TESTTEXT,SHAHashing.HASH_SHA1);
      System.out.println("The un-hashed text = " + TESTTEXT);
      System.out.println("The SHA-1 Hashed output = " + hashedText);
      Assert.assertNotNull(hashedText);
    }
    catch (Exception e)
    {
      System.out.println("There was an error doing the SHA Hash.");
    }
  }
  
  public void TestSHA256()
  {
    SHAHashing hashme = new SHAHashing();
    try
    {
      String hashedText = hashme.SHAHash(TESTTEXT,SHAHashing.HASH_SHA256);
      System.out.println("The un-hashed text = " + TESTTEXT);
      System.out.println("The SHA-256 Hashed output = " + hashedText);
      Assert.assertNotNull(hashedText);
    }
    catch (Exception e)
    {
      System.out.println("There was an error doing the SHA Hash.");
    }
  }

  public void TestSHA384()
  {
    SHAHashing hashme = new SHAHashing();
    try
    {
      String hashedText = hashme.SHAHash(TESTTEXT,SHAHashing.HASH_SHA384);
      System.out.println("The un-hashed text = " + TESTTEXT);
      System.out.println("The SHA-384 Hashed output = " + hashedText);
      Assert.assertNotNull(hashedText);
    }
    catch (Exception e)
    {
      System.out.println("There was an error doing the SHA Hash.");
    }    
    
  }
  
  public void TestSHA512()
  {
    SHAHashing hashme = new SHAHashing();
    try
    {
      String hashedText = hashme.SHAHash(TESTTEXT,SHAHashing.HASH_SHA512);
      System.out.println("The un-hashed text = " + TESTTEXT);
      System.out.println("The SHA-512 Hashed output = " + hashedText);
      Assert.assertNotNull(hashedText);
    }
    catch (Exception e)
    {
      System.out.println("There was an error doing the SHA Hash.");
    }    
    

  }
  
}
