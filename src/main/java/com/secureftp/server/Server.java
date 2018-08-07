package com.secureftp.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) throws Exception {
        // create socket
        InetAddress addr = InetAddress.getByName("0.0.0.0");
        ServerSocket servsock = new ServerSocket(13267, 50, addr);
        System.out.println("Waiting...");
        while (true) {
            Socket sock = servsock.accept();
            System.out.println("Accepted connection : " + sock);
            DataOutputStream dout = new DataOutputStream(sock.getOutputStream());
            dout.flush();

            // read file and send
            FileInputStream fis = new FileInputStream("h.pdf");
            byte[] buf = new  byte[4096];
            
            while (fis.read(buf) > 0) {
                dout.write(buf);   
            }
            // close connection
            sock.close();
            fis.close();
            dout.close();
            System.out.println("Connection closed.");
        }
    }

    public void send(OutputStream os) throws Exception {
        // sendfile
        File myFile = new File("test.txt");
        byte[] mybytearray = new byte[(int) myFile.length() + 1];
        FileInputStream fis = new FileInputStream(myFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        bis.read(mybytearray, 0, mybytearray.length);
        System.out.println("Sending...");
        os.write(mybytearray, 0, mybytearray.length);
        os.flush();
    }

    public void receiveFile(InputStream is) throws Exception {
        int filesize = 6022386;
        int bytesRead;
        int current = 0;
        byte[] mybytearray = new byte[filesize];

        FileOutputStream fos = new FileOutputStream("def.txt");
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        bytesRead = is.read(mybytearray, 0, mybytearray.length);
        current = bytesRead;

        do {
            bytesRead = is.read(mybytearray, current,
                    (mybytearray.length - current));
            if (bytesRead >= 0)
                current += bytesRead;
        } while (bytesRead > -1);

        bos.write(mybytearray, 0, current);
        bos.flush();
        bos.close();
    }
} 
