/***********************************************************************************
 * <pre>
 * Class: SHAHashing.java
 * Package: com.rk.encryptionutils
 *
 * </pre>
 * 
 * @beaninfo Description: This class will do SHA Hashing.
 *
 * @author rknechtel
 * @created May 5, 2016
 *
 *          <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
  *  rknechtel            May 5, 2015   Created
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
package com.rk.encryptionutils;


import org.apache.commons.codec.digest.DigestUtils;

/**
 * <pre>
 *  Requires Dependency:
 *      <dependency>
 *           <groupId>commons-codec</groupId>
 *           <artifactId>commons-codec</artifactId>
 *           <version>1.10</version>
 *       </dependency>
 * </pre>
 */

public class SHAHashing
{
  
  public static final int HASH_SHA1 = 1;
  public static final int HASH_SHA256 = 256;
  public static final int HASH_SHA384 = 384;
  public static final int HASH_SHA512 = 523;
  
  public static void main(String[] args)throws Exception
  {
     String texttohash = null;
     String hashedtext = null;
     
     if(args != null && args.length > 0)
     {
       texttohash = args[0];
       
       hashedtext = SHAHash(texttohash , HASH_SHA256);
       System.out.println("SHA-256 Hash = " + hashedtext);

       hashedtext = SHAHash(texttohash , HASH_SHA384);
       System.out.println("SHA-384 Hash = " + hashedtext);
       
       hashedtext = SHAHash(texttohash , HASH_SHA512);
       System.out.println("SHA-512 Hash = " + hashedtext);
       
     }
  }


  /**************************************************************
   * <pre>
   * Method: SHAHash()
   * Description: This will hash a string using SHA-256, SHA-384
   *              or SHA-512
   * </pre>
   * @param pText   (Text to Hash)
   * @param pMethod (SHA Hash Method - See Constants)
   * @return
   * @throws Exception
   *************************************************************/
  public static String SHAHash(String pText, int pMethod) throws Exception
  {

    String shaHex = null;

    switch(pMethod){
      case HASH_SHA1:
      {
        shaHex = DigestUtils.sha1Hex(pText); 
        break;
      }      
      case HASH_SHA256:
      {
        shaHex = DigestUtils.sha256Hex(pText); 
        break;
      }
      case HASH_SHA384:
      {
        shaHex = DigestUtils.sha384Hex(pText);
        break;
      }
      case HASH_SHA512:
      {
        shaHex = DigestUtils.sha512Hex(pText);
        break;
      }
    }
    
    
    System.out.println("SHA-" + pMethod + " Hash = " + shaHex);
    
    return shaHex;
    
  } // End of SHAHash()
  
  
} // End of Class SHAHashing
