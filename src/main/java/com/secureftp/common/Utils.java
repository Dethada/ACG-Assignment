package com.secureftp.common;

import java.io.File;
import java.text.SimpleDateFormat;

public class Utils {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    /**
     * List all the files and folders from a directory
     * 
     * @param directoryName Path of the target directoy
     * @return String with file details of the specified directory
     */
    public static String listFilesAndFolders(String directoryName) throws NullPointerException {
        File directory = new File(directoryName);
        String output = "";
        // get all the files from a directory
        File[] fList = directory.listFiles();
        for (File file : fList) {
            output += fileDetails(file);
        }
        return output;
    }

    /**
     * Get the details of a file
     * @param file A file
     * @return String containing the details of the file
     */
    private static String fileDetails(File file) {
        String details = "";
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        String rwx = file.canRead() ? "r" : "-";
        rwx += file.canWrite() ? "w" : "-";
        rwx += file.canExecute() ? "x" : "-";

        if (file.isDirectory()) {
            details += ANSI_BLUE + rwx + "\t" + file.length() + "\t" + sdf.format(file.lastModified()) + "\t"
                    + file.getName() + ANSI_RESET + "\n";
        } else {
            details += rwx + "\t" + file.length() + "\t" + sdf.format(file.lastModified()) + "\t" + file.getName()
                    + "\n";
        }
        return details;
    }

    /**
     * Changes directory for user
     * @return null if directory does not exist
     */
    public static String changeDir(String cwd, String change) {
        if (change.matches("((..\\/)|\\.{2}$)+")) {
            String newdir = "/";
            String[] dirs = cwd.split("/");
            int count = change.split("/").length;
            for (int i = 0; i < dirs.length - count; i++) {
                if (dirs[i].startsWith("/")) {
                    newdir += dirs[i];
                } else {
                    newdir += "/" + dirs[i];
                }
            }
            if (newdir.startsWith("//")) {
                newdir = newdir.substring(1);
            }
            File file = new File(newdir);
            if (file.isDirectory() && file.canExecute()) {
                return newdir;
            } else {
                return null;
            }
        } else if (change.startsWith("/")) {
            File file = new File(change);
            if (file.isDirectory() && file.canExecute()) {
                return change;
            } else {
                return null;
            }
        } else {
            String tmp = cwd + "/" + change;
            File file = new File(tmp);
            if (file.isDirectory() && file.canExecute()) {
                return tmp;
            } else {
                return null;
            }
        }
    }
}