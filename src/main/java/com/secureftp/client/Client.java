package com.secureftp.client;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Client {
    public static void main(String[] args) throws Exception {

//        long start = System.currentTimeMillis();

        // localhost for testing
        Socket sock = new Socket("127.0.0.1", 13267);
        System.out.println("Connecting...");
        InputStream is = sock.getInputStream();
        FileOutputStream fos = new FileOutputStream("dev.pdf");
        byte[] buf = new byte[4096];
        int count;
        while ((count = is.read(buf)) > 0) {
            fos.write(buf, 0 , count);
        }
        // receive file
//        new FileClient().receiveFile(is);
//        OutputStream os = sock.getOutputStream(); 
        //new FileClient().send(os);
//        long end = System.currentTimeMillis();
//        System.out.println("Time taken: " + (int) (end - start));

        sock.close();
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
        byte[] mybytearray = new byte[is.available()];
        is.read(mybytearray);

        FileOutputStream fos = new FileOutputStream("def.txt");
        fos.write(mybytearray);
//        BufferedOutputStream bos = new BufferedOutputStream(fos);
//
//        bos.write();
        System.out.println(new String (mybytearray));
//        bos.flush();
//        bos.close();
        fos.close();
    }
} 