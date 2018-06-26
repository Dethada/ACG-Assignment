/**
 * Client.java
 *  
 * @author Anurag Jain & Calvin Siak
 * 
 * A simple FTP client using Java Socket.
 * 
 * Read more at http://mrbool.com/file-transfer-between-2-computers-with-java/24516#ixzz3ZB8c5M00  
 */

import java.security.*;
import java.net.*; 
import java.io.*;
import java.nio.file.*;

public class Client { 
  public static void main(String [] args) throws IOException {
    String fname = "image.jpg";
    
    
    Socket socket = new Socket("127.0.0.1",15123);
    DataInputStream in = null;
    try{ in = new DataInputStream(socket.getInputStream()); }
    catch (Exception ee)
    { System.out.println("Check connection please");
      socket.close(); return;
    }
    FileOutputStream fos = new FileOutputStream(fname);

    try
    {while (true)
       fos.write(in.readByte());
    }
    catch (EOFException ee)
    {  System.out.println("File transfer complete");
       in.close();
    }
    fos.flush();
    fos.close();
    socket.close();
      
    // Print MD5
      MessageDigest myMD5 = null;
      try{ myMD5 = MessageDigest.getInstance("MD5"); }
      catch (Exception ee){}
      byte[] bFile = Files.readAllBytes(Paths.get(fname));
      myMD5.update(bFile, 0, bFile.length);
      byte[] md = myMD5.digest();
      System.out.println("MD5 = " +  asHex(md) );
      
  }
    
    public static String asHex (byte buf[]) {
        
        //Obtain a StringBuffer object
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;
        
        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        // Return result string in Hexadecimal format
        return strbuf.toString();
    }
}
