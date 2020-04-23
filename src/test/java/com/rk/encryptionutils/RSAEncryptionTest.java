package com.rk.encryptionutils;

import org.junit.Test;

public class RSAEncryptionTest {
  
  // Home:
  private static String HOME_PATH="C:\\Projects_Java\\NewProjects";
  private static String FULLPATHPUBLICKEYFILE3072 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\rsapublic3072.key";
  private static String FULLPATHPRIVATEKEYFILE3072 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\rsaprivate3072.key";
  private static String FULLPATHKPUBLICEYFILE2048 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\rsapublic2048.key";
  private static String FULLPATHPRIVATEKEYFILE2048 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\rsaprivate2048.key";
  private static String FULLPATHPUBLICKEYFILE1024 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\rsapublic1024.key";
  private static String FULLPATHPRIVATEKEYFILE1024 = HOME_PATH + "\\encryption-utils\\src\\test\\resources\\com\\rk\\encryptionutils\\keys\\rsaprivate1024.key";
  
  @Test
  public void generateKeysTest() {
    RSAEncryptionUtils utils = new RSAEncryptionUtils();
    //utils.createKeys(RSAEncryptionUtils.KEYSIZE_3072, FULLPATHPRIVATEKEYFILE3072, FULLPATHPUBLICKEYFILE3072);
    //utils.createKeys(RSAEncryptionUtils.KEYSIZE_2048, FULLPATHPRIVATEKEYFILE2048, FULLPATHKPUBLICEYFILE2048);
    //utils.createKeys(RSAEncryptionUtils.KEYSIZE_1024, FULLPATHPRIVATEKEYFILE1024, FULLPATHPUBLICKEYFILE1024);
  }
  
  
  
} // End of Test RSAEncryptionTest
