/***********************************************************************************
 * <pre>
 * Class: Base64EncodingUtils.java
 * Package: com.rk.encryptionutils
 * 
 * @beaninfo Description: Class for doing Base64 Encoding/Decoding
 * </pre>
 * 
 * 
 * @author rknechtel
 * @created Oct 3, 2012
 * 
 *  <pre>
 *  Mutation/Modification Log
 *  Name                  Date          Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel             Oct 3, 2012   Created
 *  rknechtel             Feb 14, 2014  Added decoding and writing binary
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.codec.binary.Base64;

public class Base64EncodingUtils
{

  public Base64EncodingUtils()
  {
  }

  /*****************************************************
   * <pre>
   * Method: main()
   * Description: main method for command line usage
   * </pre>
   * 
   * @param String
   *          [] args
   ****************************************************/
  public static void main(String[] args)
  {
    String usage = "Usage:\n For Encoding: java com.rk.encryptionutils.Base64EncodingUtils ecode mystringtoencode\n For Decoding: java com.rk.encryptionutils.Base64EncodingUtils decode mystringtodecode\n";
    Base64EncodingUtils encodeUtils = new Base64EncodingUtils();

    if (args != null && args.length > 0 && args.length == 2)
    {
      String toDo = args[0];
      String text = args[1];

      if (toDo != null && toDo.trim().equalsIgnoreCase("encode"))
      {
        String encodedText = encodeUtils.encodeBase64(text);
        System.out.println("The Encoded value of " + text + " is: " + encodedText);
      }
      else if (toDo != null && toDo.trim().equalsIgnoreCase("decode"))
      {
        String decodedText = encodeUtils.decodeBase64(text);
        System.out.println("The Decoded value of " + text + " is: " + decodedText);
      }
      else
      {
        System.out.println(usage);
      }

      // Clean Up
      encodeUtils = null;
      toDo = null;
      text = null;
    }
    else
    {
      System.out.println(usage);
    }
  } // End of main()

  /*****************************************************
   * <pre>
   * Method: encodeBase64()
   * Description: Encode passed in text as Base64
   * </pre>
   * 
   * @param (String) pText
   * @return (String)
   ****************************************************/
  public String encodeBase64(String pText)
  {
    String textToEncode = "";
    byte[] encodedBytes = Base64.encodeBase64(pText.getBytes());
    textToEncode = new String(encodedBytes);

    return textToEncode;
  } // End of encodeBase64()

  /*****************************************************
   * <pre>
   * Method: encodeBase64Bin()
   * Description: Encode passed in text as Base64 Binary
   * </pre>
   * 
   * @param (String) pText
   * @return (byte[])
   ****************************************************/
  public byte[] encodeBase64Bin(String pText)
  {
    String textToEncode = "";
    byte[] encodedBytes = Base64.encodeBase64(pText.getBytes());
    textToEncode = new String(encodedBytes);

    return textToEncode.getBytes();
  } // End of encodeBase64Bin()

  /*********************************************
   * 8
   * 
   * <pre>
   * Method: decodeBase64()
   * Description: Decode Text from Base64
   * </pre>
   * 
   * @param (String) pText
   * @return (String)
   *********************************************/
  public String decodeBase64(String pText)
  {
    String textToDecode = "";
    byte[] decodedBytes = Base64.decodeBase64(pText);
    textToDecode = new String(decodedBytes);

    return textToDecode;
  } // End of decodeBase64()

  /*********************************************
   * 8
   * 
   * <pre>
   * Method: decodeBase64Bin()
   * Description: Decode Binary from Base64
   * </pre>
   * 
   * @param (String) pText
   * @return (byte[])
   *********************************************/
  public byte[] decodeBase64Bin(String pText)
  {
    String textToDecode = "";
    byte[] decodedBytes = Base64.decodeBase64(pText);
    textToDecode = new String(decodedBytes);

    return textToDecode.getBytes();
  } // End of decodeBase64Bin()

  /*********************************************
   * <pre>
   * Method: writeBinary
   * Description: Will write a binary file
   * </pre>
   * 
   * @param (byte[]) pBytes
   * @param (String) pFilePathName
   *********************************************/
  public void writeBinary(byte[] pBytes, String pFilePathName) throws FileNotFoundException, IOException
  {
    File theFile = new File(pFilePathName);
    FileOutputStream fos = new FileOutputStream(theFile);
    fos.write(pBytes);
    fos.flush();
    fos.close();
  } // End of writeBinary()

} // End of Base64EncodingUtils
