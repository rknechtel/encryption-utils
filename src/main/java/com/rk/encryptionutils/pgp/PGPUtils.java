/***********************************************************************************
 * <pre>
 * Class: PGPUtils.java
 * Package: com.rk.encryptionutils.pgp
 *
 * </pre>
 * @beaninfo Description: This is a collection of PGP Utils
 * PGP encryption uses a serial combination of hashing, data compression, symmetric-key 
 * cryptography, and, finally, public-key cryptography; each step uses one of several 
 * supported algorithms. Each public key is bound to a user name and/or an e-mail address. 
 * The first version of this system was generally known as a web of trust to contrast with 
 * the X.509 system which uses a hierarchical approach based on certificate authority and 
 * which was added to PGP implementations later. Current versions of PGP encryption include 
 * both options through an automated key management server.
 * 
 *
 * @author rknechtel
 * @created May 6, 2016
 *
 * <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 * </pre>
 *  rknechtel              May 6, 2016        Created
 *
 **********************************************************************************/
package com.rk.encryptionutils.pgp;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;


public class PGPUtils
{

  
  
  /********************************************************************
   * <pre>
   * Method: getSHAHashs()
   * Description: This will return a HashMap of the SHA Hash types
   * </pre>
   * @return
   ********************************************************************/
  private Map<String, Integer> getSHAHashs()
  {
      HashMap<String, Integer> shas = new HashMap<String, Integer>();
      shas.put("SHA1", HashAlgorithmTags.SHA1);
      shas.put("SHA224", HashAlgorithmTags.SHA224);
      shas.put("SHA256", HashAlgorithmTags.SHA256);
      shas.put("SHA384", HashAlgorithmTags.SHA384);
      shas.put("SHA512", HashAlgorithmTags.SHA512);        
      return shas;
  } // End of getSHAHashs()
  
  /*****************************************************************
   * <pre>
   * Method: getAESModes()
   * Description: This will return a HashMap of the AES modes
   * </pre>
   * @return
   ****************************************************************/
  private Map<String, Integer> getAESModes()
  {
      HashMap<String, Integer> aes = new HashMap<String, Integer>();
      aes.put("AES_128", PGPEncryptedData.AES_128);
      aes.put("AES_192", PGPEncryptedData.AES_192);
      aes.put("AES_256", PGPEncryptedData.AES_256);
      
      return aes;
  } // End of getAESModes()
  
} // Ned of Class PGPUtils
