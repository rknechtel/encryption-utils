/***********************************************************************************
 * <pre>
 * Class: RSAPGPKeyGen.java
 * Package: com.rk.encryptionutils.keygenerators
 *
 * </pre>
 * 
 * @beaninfo Description: This class will generate RSA Keys using AES and 
 *                        SHA hashing.
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
package com.rk.encryptionutils.keygenerators;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

public class RSAPGPKeyGen
{
  
  public static void main(String args[]) throws Exception
  {
    String emailAddy = null;
    String password = null;
    String aesMode = null;
    String shaMode = null;
    String rsaKeySize = null;
    
    if (args.length < 5)
    {
      System.err.println("Usage:");
      System.err.println("java -cp encryption-utils.jar com.rk.encryptionutils.keygenerators.RSAPGPKeyGen arg1 arg2 arg3 arg4 arg5");
      System.err.println("arg1 = Email Address");
      System.err.println("arg2 = Password");
      System.err.println("arg3 = AES Mode (128, 192, 256)");
      System.err.println("arg4 = SHA Mode (1, 224, 256, 384, 512)");
      System.err.println("arg5 = RSA Key Size (1024, 2048, 3072, 4096)");
      System.exit(1);
    }
    
    emailAddy = args[0].trim();
    password = args[1].trim();
    aesMode = args[2].trim();
    shaMode = args[3].trim();
    rsaKeySize = args[4].trim();

    PGPKeyRingGenerator krgen = generateKeyRing(emailAddy, password.toCharArray(), Integer.parseInt(aesMode), Integer.parseInt(shaMode), Integer.parseInt(rsaKeySize));

    // Generate public key ring, dump to file.
    PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
    BufferedOutputStream pubout = new BufferedOutputStream(new FileOutputStream("RSAPublicKeyRing.pkr"));
    pkr.encode(pubout);
    pubout.close();

    // Generate private key, dump to file.
    PGPSecretKeyRing skr = krgen.generateSecretKeyRing();
    BufferedOutputStream secout = new BufferedOutputStream(new FileOutputStream("RSAPrivateKeyRing.skr"));
    skr.encode(secout);
    secout.close();
  }

  /*******************************************************************
   * <pre>
   * Method:generateKeyRing()
   * Description: This will generate an RSA PGP Key Ring.
   * </pre>
   * @param pEmail
   * @param pPassword
   * @param pAESMode
   * @param pSHAMode
   * @param pRSAKeySize
   * @return
   * @throws Exception
   ********************************************************************/
  public final static PGPKeyRingGenerator generateKeyRing(String pEmail, char[] pPassword, int pAESMode, int pSHAMode, int pRSAKeySize) throws Exception
  {
    return keyRingGenerator(pEmail, pPassword, pAESMode, pSHAMode, pRSAKeySize, 0xc0);
  } // End of generateKeyRing()

  /*****************************************************************************************************************************
   * <pre>
   * Note: s2kcount is a number between 0 and 0xff that controls the number of times to iterate the password hash before use. 
   * More iterations are useful against offline attacks, as it takes more time to check each password. 
   * The actual number of iterations is rather complex, and also depends on the hash function in use.
   * Refer to Section 3.7.1.3 in rfc4880.txt. 
   * Bigger numbers give you more iterations. As a rough rule of thumb, when using SHA256 as the hashing function, 
   * 0x10 gives you about 64 iterations, 0x20 about 128, 0x30 about 256 and so on till 0xf0,
   * or about 1 million iterations. 
   * The maximum you can go to is 0xff, or about 2 million iterations. I'll use 0xc0 as a default -- about 130,000 iterations.
   * </pre>
  ******************************************************************************************************************************/


  /*************************************************************************
   * <pre>
   * Method: keyRingGenerator()
   * Description: This will generate an RSA PGP Key Ring.
   * </pre>
   * @param id
   * @param pass
   * @param pAESMode
   * @param pSHAMode
   * @param pRSAKeySize
   * @param s2kcount
   * @return
   * @throws Exception
   *************************************************************************/
  public final static PGPKeyRingGenerator keyRingGenerator(String id, char[] pass, int pAESMode, int pSHAMode, int pRSAKeySize, int s2kcount) throws Exception
  {
    PGPDigestCalculator shaCalc = null;
    BcPGPContentSignerBuilder csb = null;
    PBESecretKeyEncryptor pske = null;
    int sha = 0;
    int aes = 0;
    
    switch(pSHAMode)
    {
      case 1:
        sha = HashAlgorithmTags.SHA1;
        break;
      case 224:
        sha = HashAlgorithmTags.SHA224;
        break;
      case 256:
        sha = HashAlgorithmTags.SHA256;
        break;
      case 384:
        sha = HashAlgorithmTags.SHA384;
        break;
      case 512:
        sha = HashAlgorithmTags.SHA512;
        break;          
    }
    
    switch(pAESMode)
    {
      case 128:
        aes = PGPEncryptedData.AES_128;
        break;
      case 192:
        aes = PGPEncryptedData.AES_192;
        break;        
      case 256:
        aes = PGPEncryptedData.AES_256;
        break;        
    }
    
    // This object generates individual key-pairs.
    RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

    // Boilerplate RSA parameters, no need to change anything except for the RSA key-size (2048). 
    // You can use whatever RSA key-size that makes sense for you -- 1024, 2048, 3072, 4096, etc.
    kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), pRSAKeySize, 12));

    // First create the master (signing) key with the generator.
    PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
    
    // Then an encryption subkey.
    PGPKeyPair rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

    // Add a self-signature on the id
    PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();

    // Add signed metadata on the signature.
    // 1) Declare its purpose
    signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
    
    // 2) Set preferences for secondary crypto algorithms to use when sending messages to this key.
    signhashgen.setPreferredSymmetricAlgorithms(false, new int[] { SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128 });
    
    signhashgen.setPreferredHashAlgorithms(false, new int[] { HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA224, HashAlgorithmTags.SHA1 });
    
    // 3) Request senders add additional checksums to the message (useful when verifying unsigned messages.)
    signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

    // Create a signature on the encryption subkey.
    PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
    
    // Add metadata to declare its purpose
    enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

    // Object used to encrypt the secret key. 
    // shaCalc = new BcPGPDigestCalculatorProvider().get(sha);
    shaCalc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1); // Only SHA-1 Supported.
    csb = new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(), sha); // SHA Hash Algorithm.

    // bcpg 1.48 exposes this API that includes s2kcount. Earlier versions used a default of 0x60. 
    // Use AES Encryption Algorithm and SHA Hash Algorithm
    pske = (new BcPBESecretKeyEncryptorBuilder(aes, shaCalc, s2kcount)).build(pass);
    
    // Finally, create the keyring itself. The constructor takes parameters that allow it to generate the self signature.
    PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign, id, shaCalc, signhashgen.generate(), null, csb, pske);

    // Add our encryption subkey, together with its signature.
    keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null);
    
    return keyRingGen;
  } // End of keyRingGenerator()
  
} // End of Class RSAPGPKeyGen
