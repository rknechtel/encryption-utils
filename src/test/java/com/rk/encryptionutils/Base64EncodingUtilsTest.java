package com.rk.encryptionutils;

import org.junit.Test;

public class Base64EncodingUtilsTest
{


  @Test
  public void encodeStringTest()
  {
    Base64EncodingUtils encodeUtils = new Base64EncodingUtils();
    String encoded = encodeUtils.encodeBase64("mytexttoencode");
    assert("bXl0ZXh0dG9lbmNvZGU=".equals(encoded));
  } // End of Test encodeStringTest()
  
  @Test
  public void decodeStringTest()
  {
    Base64EncodingUtils encodeUtils = new Base64EncodingUtils();
    String decoded = encodeUtils.decodeBase64("bXl0ZXh0dG9lbmNvZGU=");
    assert("mytexttoencode".equals(decoded));
  } // End of Test decodeStringTest()
  
}
