package com.secureftp.common;

import java.util.Date;
import java.text.SimpleDateFormat;
import com.secureftp.common.Utils;

public class Logger{
	private boolean VERBOSE;
	
	/**
	 * Initalize Logger
	 * @param 	verbose	Determines amound of details printed
	 */
	public Logger(boolean verbose){
		VERBOSE = verbose;
	}
	
	/**
	 * Print out log message to stdout
	 * @param	type	Log message type
	 * @param	msg		Log message
	 */
	private void log(String type, String msg){
		String prefix = type.equals("error") ? Utils.ANSI_RED : Utils.ANSI_CYAN;
		System.out.println(prefix + "[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg + Utils.ANSI_RESET);
	}
	
	/**
	 * Print log message to stdout
	 * @param	type	Log message type
	 * @param	msg		Log message
	 * @param	e		Exception which occurred
	 */
	private void log(String type, String msg, Exception e){
		String prefix = type.equals("error") ? Utils.ANSI_RED : Utils.ANSI_CYAN;
		if (VERBOSE){
			System.out.println(prefix + "[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg + Utils.ANSI_RESET);
			e.printStackTrace();
		} else {
			System.out.println(prefix + "[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + ' ' + msg + Utils.ANSI_RESET);
			System.out.println(prefix + "[" + type + "]" + " - " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()) + " Exception: " + e.getMessage() + Utils.ANSI_RESET);
		}
	}
	
	/**
	 * Prints error message
	 * @param	msg	Message to print
	 */
	public void error(String msg) {
        log("ERROR", msg);
    }
	
	/**
	 * Prints error message
	 * @param	msg	Message to print
	 * @param	e	Exception which occured
	 */
	public void error(String msg, Exception e) {
        log("ERROR", msg, e);
    }
	
	/**
	 * Print Info message
	 * @param	msg	Message to print
	 */
	public void info(String msg){
		log("INFO", msg);
	}
	
	/**
	 * Print out verbose messages
	 * @param	msg	Message to print
	 */
	public void verbose(String msg){
		if (VERBOSE) log("VERB", msg);
	}
}