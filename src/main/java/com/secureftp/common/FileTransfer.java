package com.secureftp.common;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;

public class FileTransfer {
    /**
     * Sends a file over ObjectOutputStream
     * 
     * @param fullfilename The absolute path of the file to be sent
     * @param out          The stream the file is going to be sent over
     */
    public static void sendFile(String fullfilename, ObjectOutputStream out) throws IOException {
        String[] tmp = fullfilename.split("/");
        String fname = tmp[tmp.length - 1];
        File targetfile = new File(fullfilename);
        if (!targetfile.exists()) {
            out.writeUTF("File does not exist " + fullfilename);
            out.flush();
            return;
        }
        if (!canReadFile(targetfile)) {
            out.writeUTF("Permission denied.");
            out.flush();
            return;
        }
        // indicate start of a file transfer
        out.writeUTF("SFO");
        out.flush();
        out.writeUTF(fname);
        out.flush();
        long flength = targetfile.length();
        out.writeLong(flength);
        out.flush();
        DataInputStream dis = new DataInputStream(new FileInputStream(fullfilename));

        try {
            for (long i = 0; i < flength; i++) {
                out.writeByte(dis.readByte());
            }
            out.flush();
        } finally {
            out.writeUTF(hashFile(fullfilename));
            out.flush();
            dis.close();
        }
    }

    /**
     * Recieves a file from ObjectInputStream
     * 
     * @param in   Stream used for recieving the file
     * @param cdir The directory that we are going to recieve the file in
     * @return null if data is corrupted
     */
    public static String recvFile(ObjectInputStream in, String cdir) throws IOException {
        String fname = in.readUTF();
        Long flength = in.readLong();
        String fullpath = cdir + "/" + fname;
        FileOutputStream fos = new FileOutputStream(fullpath);
        for (long i = 0; i < flength; i++) {
            fos.write(in.read());
        }
        fos.flush();
        fos.close();
        // validate file integirty
        if (!in.readUTF().equals(hashFile(fullpath))) {
            FileUtils.deleteQuietly(new File(fullpath));
            return null;
        }
        return fullpath;
    }

    /**
     * Check if file can be read
     * 
     * @return true if file can be read, else return false
     */
    private static boolean canReadFile(File file) {
        try {
            FileReader fileReader = new FileReader(file.getAbsolutePath());
            fileReader.read();
            fileReader.close();
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Hashes a file with sha1
     * 
     * @return The Hash in hex string
     */
    private static String hashFile(String fname) throws IOException {
        return DigestUtils.sha1Hex(Files.newInputStream(Paths.get(fname)));
    }
}