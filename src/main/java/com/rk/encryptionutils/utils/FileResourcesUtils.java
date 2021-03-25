/***********************************************************************************
 * <pre>
 * Class: FileResourcesUtils.java
 * Package: com.rk.encryptionutils.utils
 * 
 * </pre>
 * 
 * @beaninfo Description: Class with a collection of File Rousource Utiliites
 * 
 * @author rknechtel
 * @created Sep 28, 2012
 * 
 *          <pre>
 *  Mutation/Modification Log
 *  Name                  Date               Comments
 *  -------------------------------------------------------------------------------
 *  rknechtel              March 24, 2021    Created
 * </pre>
 * 
 **********************************************************************************/
package com.rk.encryptionutils.utils;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public class FileResourcesUtils
{

 /***************************************************************************************************
  * <pre>
  * Method: getFileFromResourceAsStream()
  * Description: Will get a file from the resources folder.
  *              Works everywhere, IDE, unit test and JAR file.
  * </pre>
  * 
  * @param (String) pFileName
  * @return (InputStream)
 * @throws URISyntaxException
  **************************************************************************************************/
  public InputStream getFileFromResourceAsStream(String pFileName) 
  {

    // The class loader that loaded the class
    ClassLoader classLoader = getClass().getClassLoader();
    InputStream inputStream = classLoader.getResourceAsStream(pFileName);

    // the stream holding the file content
    if(inputStream == null)
    {
      try
      {
        File newfile = getFileFromResource(pFileName);
        inputStream = new FileInputStream(newfile);
      }
      catch(URISyntaxException use)
      {
        throw new IllegalArgumentException("getFileFromResourceAsStream: URISyntaxException - File not found! " + pFileName);
      }
      catch(FileNotFoundException fnfe)
      {
        throw new IllegalArgumentException("getFileFromResourceAsStream: FileNotFoundException - File not found! " + pFileName);
      }
      //throw new IllegalArgumentException("getFileFromResourceAsStream: File not found! " + pFileName);
    }

    return inputStream;

  } // End of getFileFromResourceAsStream()


 /***************************************************************************************************
  * <pre>
  * Method: getFileFromResource()
  * Description: Will get a file from a folder.
  *              The resource URL does not working in a JAR
  *               If you try to access a file that is inside a JAR,
  *               It will throw a: 
  *               InvalidPathException (Windows)
  *               NoSuchFileException (Linux) 
  * </pre>
  * 
  * @param (String) pFileName
  * @return (File)
  **************************************************************************************************/
  public File getFileFromResource(String pFileName) throws URISyntaxException
  {

    ClassLoader classLoader = getClass().getClassLoader();
    URL resource = classLoader.getResource(pFileName);
    if(resource == null)
    {
      throw new IllegalArgumentException("getFileFromResource: File not found! " + pFileName);
    }
    else
    {

      // failed if files have whitespaces or special characters
      //return new File(resource.getFile());

      return new File(resource.toURI());
    }

  } // End of getFileFromResource()


 /***************************************************************************************************
  * <pre>
  * Method: printInputStream()
  * Description: Will print an input stream.
  * </pre>
  * 
  * @param (InputStream) pIs
  **************************************************************************************************/
  public static void printInputStream(InputStream pIs)
  {

    try (InputStreamReader streamReader = new InputStreamReader(pIs, StandardCharsets.UTF_8);
        BufferedReader reader = new BufferedReader(streamReader))
    {

      String line;
      while ((line = reader.readLine()) != null)
      {
        System.out.println(line);
      }

    }
    catch(IOException ioe)
    {
      System.out.println("FileResourcesUtils: printInputStream() IOException - Error = " + ioe.getMessage());
    }

  } // End of printInputStream()


/***************************************************************************************************
  * <pre>
  * Method: printInputStream()
  * Description: Will print a file.
  * </pre>
  * 
  * @param (File) pFile
  **************************************************************************************************/
  public static void printFile(File pFile)
  {

    List<String> lines;
    try
    {
      lines = Files.readAllLines(pFile.toPath(), StandardCharsets.UTF_8);
      lines.forEach(System.out::println);
    }
    catch(IOException ioe)
    {
        System.out.println("FileResourcesUtils: printFile() IOException - Error = " + ioe.getMessage());
    }

  } // End of printFile()

} // End of Class FileResourcesUtils