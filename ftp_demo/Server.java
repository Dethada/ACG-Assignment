/**
 * Server.java
 *  
 * @author Anurag Jain & Calvin Siak
 * 
 * A simple FTP server using Java ServerSocket.
 * 
 * Read more at http://mrbool.com/file-transfer-between-2-computers-with-java/24516#ixzz3ZB7wUAo8   
 */ 

import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;

public class Server { 
  public static void main (String [] args ) throws IOException { 
    ServerSocket serverSocket = new ServerSocket(15123);
    Socket socket = null;
    while(true)
    {
        socket = serverSocket.accept();
        System.out.println("Accepted connection : " + socket.getRemoteSocketAddress().toString() + " <-> /127.0.0.1:15123" );

        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        
          
        // get the image from a webcam
        URL myimage = new URL("http://183.76.13.58:80/SnapshotJPEG?Resolution=640x480");
        DataInputStream in = null;
        try{ in = new DataInputStream(myimage.openStream()); }
        catch (Exception ee)
        { System.out.println("Check internet connection please");
          socket.close(); return;
        }
          
        DateFormat dateFormat = new SimpleDateFormat("yy/MM/dd HH:mm:ss");
        Date date = new Date();
        System.out.println("Sending image " + dateFormat.format(date) );
          
        try
        { while (true) { dos.writeByte(in.readByte()); } }
        catch (EOFException ee)
          { System.out.println("-------------- Done ----------"); in.close();}
          
        dos.flush();
        dos.close();
        socket.close();
    }
    
  } 
}

