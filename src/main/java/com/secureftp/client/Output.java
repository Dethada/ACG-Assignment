package com.secureftp.client;

import com.secureftp.common.Utils;

public class Output {
    /**
     * Prints a error message
     * @param msg The message to be printed
     */
    public static void error(String msg) {
        System.out.println(Utils.ANSI_RED + msg + Utils.ANSI_RESET);
    }

    /**
     * Prints a info message
     * @param msg The message to be printed
     */
    public static void info(String msg) {
        System.out.println(Utils.ANSI_CYAN + msg + Utils.ANSI_RESET);
    }
}