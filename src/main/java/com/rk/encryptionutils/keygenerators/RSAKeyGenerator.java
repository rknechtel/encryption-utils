/***********************************************************************************
 * <pre>
 * Class: RSAKeyGenerator.java
 * Package: com.rk.encryptionutils.keygenerators
 *
 * </pre>
 * 
 * @beaninfo Description: This class will generate RSA Keys using SHA hashing.
 *
 * @author rknechtel
 * @created May 8, 2016
 *
 *          <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel             May 8, 2016   Created
 * </pre>
 * 
 *
 **********************************************************************************/
package com.rk.encryptionutils.keygenerators;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import org.apache.commons.codec.binary.Base64;

public class RSAKeyGenerator
{
  public static final String SHA1 = "SHA-1";
  public static final String SHA224 = "SHA-224";
  public static final String SHA256 = "SHA-256";
  public static final String SHA384 = "SHA-384";
  public static final String SHA512 = "SHA-512";

  public static void main(String[] args)
  {

    String publicKeyFilename = null;
    String privateKeyFilename = null;
    String shaMode = null;

    RSAKeyGenerator keyGenerator = new RSAKeyGenerator();

    if (args.length < 3)
    {
      System.err.println("Usage: java " + keyGenerator.getClass().getName() + " Public_Key_Filename Private_Key_Filename SHA_Mode");
      System.exit(1);
    }

    publicKeyFilename = args[0].trim();
    privateKeyFilename = args[1].trim();
    shaMode = args[2].trim();
    keyGenerator.generateRSAKeys(publicKeyFilename, privateKeyFilename, shaMode);

  }

  /**
   * <pre>
   * Method: generateRSAKeys()
   * Description: This will generate the RSA Public and Private Keys.
   * </pre>
   * @param pPublicKeyFilename
   * @param pPrivateFilename
   * @param pShaMode
   */
  public void generateRSAKeys(String pPublicKeyFilename, String pPrivateFilename, String pShaMode)
  {

    try
    {

      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

      // Create the Public and Private Keys
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

      SecureRandom random = new FixedRand(pShaMode);
      generator.initialize(1024, random);

      KeyPair pair = generator.generateKeyPair();
      Key pubKey = pair.getPublic();
      Key privKey = pair.getPrivate();

      System.out.println("publicKey : " + Base64.encodeBase64(pubKey.getEncoded()));
      System.out.println("privateKey : " + Base64.encodeBase64(privKey.getEncoded()));

      BufferedWriter out = new BufferedWriter(new FileWriter(pPublicKeyFilename));
      byte[] encodedBytes = Base64.encodeBase64(pubKey.getEncoded());
      out.write(new String(encodedBytes));
      out.close();

      out = new BufferedWriter(new FileWriter(pPrivateFilename));
      encodedBytes = Base64.encodeBase64(privKey.getEncoded());
      out.write(new String(encodedBytes));
      out.close();

    }
    catch (Exception e)
    {
      System.out.println(e);
    }
  } // End of generateRSAKeys()

  private static class FixedRand extends SecureRandom
  {

    private static final long serialVersionUID = -4622664395187224895L;
    
    MessageDigest sha;
    byte[] state;

    FixedRand(String pShaMode)
    {
      try
      {
        this.sha = MessageDigest.getInstance(pShaMode);
        this.state = sha.digest();
      }
      catch (NoSuchAlgorithmException e)
      {
        throw new RuntimeException("can't find " + pShaMode + "!");
      }
    }

    public void nextBytes(byte[] bytes)
    {

      int off = 0;

      sha.update(state);

      while (off < bytes.length)
      {
        state = sha.digest();

        if (bytes.length - off > state.length)
        {
          System.arraycopy(state, 0, bytes, off, state.length);
        }
        else
        {
          System.arraycopy(state, 0, bytes, off, bytes.length - off);
        }

        off += state.length;

        sha.update(state);
      }
    }
  }

} // End of Class RSAKeyGenerator
