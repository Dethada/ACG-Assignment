package com.secureftp.common;

import java.util.Date;
import java.text.SimpleDateFormat;
import com.secureftp.common.Utils;

public class Logger {

	/**
	 * Initalize Logger
	 */
	public Logger() {
	}

	/**
	 * Prints error message
	 * 
	 * @param msg Message
	 */
	public void error(String msg) {
		output("ERROR", msg);
	}

	/**
	 * Prints error message
	 * 
	 * @param msg Message
	 * @param e   Exception which occured
	 */
	public void error(String msg, Exception e) {
		output("ERROR", msg, e);
	}

	/**
	 * Print Info message
	 * 
	 * @param msg Message
	 */
	public void info(String msg) {
		output("INFO", msg);
	}

	/**
	 * Output message
	 * 
	 * @param type Message type
	 * @param msg  Message
	 */
	private void output(String type, String msg) {
		String prefix = type.equals("error") ? Utils.ANSI_RED : Utils.ANSI_CYAN;
		System.out.println(prefix + "[" + type + "] - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date())
				+ " - " + msg + Utils.ANSI_RESET);
	}

	/**
	 * Output message twith exception
	 * 
	 * @param type Message type
	 * @param msg  Message
	 * @param e    Exception which occurred
	 */
	private void output(String type, String msg, Exception e) {
		String prefix = type.equals("error") ? Utils.ANSI_RED : Utils.ANSI_CYAN;
		System.out.println(prefix + "[" + type + "] - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date())
				+ " - " + msg + Utils.ANSI_RESET);
		System.out.println(prefix + "[" + type + "] - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date())
				+ " Exception: " + e.getMessage() + Utils.ANSI_RESET);
	}
}