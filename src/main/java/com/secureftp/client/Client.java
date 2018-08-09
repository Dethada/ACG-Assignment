package com.secureftp.client;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import com.secureftp.common.FileTransfer;
import com.secureftp.common.Utils;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsNoCloseNotifyException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client { 
	
	private static String CACERTPATH;
	private static String HOST;
	private static int PORT=21;
	private static X509Certificate CACERT;
	private static Socket SOCKET;
	private static boolean VALID = false;
    private static ObjectOutputStream SOUT;
    private static ObjectInputStream SIN;
    private static String CWD;
    private static String HOMEDIR;

	public static void main(String [] args) throws IOException {
		Options options = new Options();
		
		Option sport = new Option("p", "port", true, "Port which server listens on (Defaults to port 21)");
		sport.setRequired(false);
		options.addOption(sport);
		
		Option shost = new Option("s", "server", true, "Address of the server");
		shost.setRequired(true);
		options.addOption(shost);
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		Option cert = new Option("c", "certificate", true, "CA Certificate");
		cert.setRequired(true);
		options.addOption(cert);

		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmdargs;
		
		try {
            cmdargs = parser.parse(options, args);

			if (cmdargs.hasOption("h")){
				System.out.println("Secure FTP Client\n");
				formatter.printHelp("java -jar Client.jar <options>", options);
				System.exit(0);
			}
			
			if (cmdargs.hasOption("s")) {
				HOST = cmdargs.getOptionValue("s");
				if (!HOST.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}")){
					System.out.println("Invalid IP detected\n");
					System.out.println("Usage: java -jar Client.jar <options>");
					System.out.println("Use -h to display help");
					System.exit(0);
				}
			}
			
			if (cmdargs.hasOption("p")) {
				try {
					PORT = Integer.parseInt(cmdargs.getOptionValue("p"));
				} catch (NumberFormatException e) {
					System.out.println("Int Expected for -p\n");
					System.out.println("Usage: java -jar Client.jar <options>");
					System.out.println("Use -h to display help");
					System.exit(0);
				}
			}
			
			if (cmdargs.hasOption("c")) {
				CACERTPATH = cmdargs.getOptionValue("c");
			}
			
        } catch (ParseException e) {
            System.out.println(e.getMessage() + '\n');
			System.out.println("Usage: java -jar Client.jar <options>");
			System.out.println("Use -h to display help");
            System.exit(1);
		}
		
		// Initialise Connection
		CWD = System.getProperty("user.dir");
        HOMEDIR = System.getProperty("user.home");
		
		// Load CA Cert
		CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
			FileInputStream readCa = new FileInputStream(CACERTPATH);
			CACERT = (X509Certificate) cf.generateCertificate(readCa);
			readCa.close();
		} catch (CertificateException e) {
			e.printStackTrace();
		}


		Output.info("Connecting to server at " + HOST + ':' + PORT);
		Security.addProvider(new BouncyCastleProvider());
		try{
            SOCKET = new Socket(HOST, PORT);
			TlsClientProtocol cproto = new TlsClientProtocol(SOCKET.getInputStream(), SOCKET.getOutputStream(), new SecureRandom());
			
            // Initialise the TLS connection
            cproto.connect(new DefaultTlsClient() {
                public TlsAuthentication getAuthentication() throws IOException {
                    return new ServerOnlyTlsAuthentication() {
                        public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
                            try {
                                X509Certificate serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(serverCertificate.getCertificateList()[0].getEncoded()));
                                verifyCert(serverCert);
                            } catch (CertificateException e) {
                                Output.error("Unable to verify server's certificate");
                            }
                        }
                    };
                }
            });

            
			// Exit if server certificate is not valid
			if (!VALID) close(1);
			
			/*
			 * Get TLS connection socket stream
			 * Traffic using this stream will be encrypted and decrypted automatically
			 */
            SOUT = new ObjectOutputStream(cproto.getOutputStream());
            SIN = new ObjectInputStream(cproto.getInputStream());
            SOUT.flush();
            System.out.println(SIN.readUTF());
            Scanner scan = new Scanner(System.in);
            String cmd = "";
            while (!(cmd.equals("exit") || cmd.equals("quit") || cmd.equals("bye"))) {
                System.out.print("> ");
                cmd = scan.nextLine().trim();

                if (cmd.equals("SFO")) {
                    System.out.println(Utils.ANSI_RED + "Invalid Command. Type help to show available commands." + Utils.ANSI_RESET);
                    continue;
                } else if (cmd.startsWith("put ")) {
                    String[] tmp = cmd.split("\\s");
					try {
						if (tmp[1].startsWith("/")) {
							FileTransfer.sendFile(tmp[1], SOUT);
						} else {
							FileTransfer.sendFile(CWD + "/" +tmp[1], SOUT);
						}
					} catch(IOException e) {
						Output.error("Send file " + tmp[1] + " failed\n" + e.getMessage());
						System.out.print(Utils.ANSI_RED + "Exception occured\n" + Utils.ANSI_RESET);
                    }
                    continue;
                } else if (cmd.equals("lls")) {
                    System.out.println(Utils.listFilesAndFolders(CWD));
                    continue;
                } else if (cmd.startsWith("lls ")) {
					String[] tmp = cmd.split("\\s");
					try {
						System.out.println(Utils.listFilesAndFolders(tmp[1]));
					} catch (NullPointerException e) {
						System.out.println(Utils.ANSI_RED + "Invalid directory" + Utils.ANSI_RESET);
                    }
                    continue;
                } else if (cmd.equals("lcd")) {
					CWD = HOMEDIR;
                    System.out.println(Utils.ANSI_GREEN + "Changed directory to " + HOMEDIR + Utils.ANSI_RESET);
                    continue;
				} else if (cmd.startsWith("lcd ")) {
					String[] tmp = cmd.split("\\s");
					String tmpDir = Utils.changeDir(CWD, tmp[1]);
					if (tmpDir != null) {
						CWD = tmpDir;
						System.out.println(Utils.ANSI_GREEN + "Changed directory to " + tmp[1] + Utils.ANSI_RESET);
					} else {
						System.out.println(Utils.ANSI_RED + "Invalid directory" + Utils.ANSI_RESET);
					}
                    continue;
				} else if (cmd.equals("lpwd")) {
                    System.out.println(CWD);
                    continue;
				}

                sendCMD(cmd);
                String reply = SIN.readUTF();
                if (reply.equals("SFO")) {
                    try {
						String fname = FileTransfer.recvFile(SIN, CWD);
						if (fname != null) {
							Output.info("Recieved " + fname);
						} else {
							Output.error("File integrity compromised during transfer.");
						}
                    } catch (IOException e) {
                        System.out.println("Error occured when recieving file.");
                    }
                } else {
                    System.out.println(reply);
                }
            }
            scan.close();
            close(0);
		} catch (SocketException e) {
			Output.error("Failed to connect to server");
		} catch (TlsNoCloseNotifyException e) {
			Output.error("Connection closed by server");
			System.exit(1);
		} catch (Exception e){
			Output.error("An error occurred " + e.getMessage());
		}
	}

	/**
	 * Sends a command to the server
	 * @param  	cmd		Command to be sent to the server
	 * @return	true if message sent successfully, false if it failed.
	 */
    private static boolean sendCMD(String cmd) {
        try {
            SOUT.writeUTF(cmd);
            SOUT.flush();
            return true;
		} catch (IOException e) {
			Output.error("Can't connect to server.");
            return false;
        }
    }
	
	/**
	 * Verifies Server Certificate
	 * @param  	servCert				Server Certificate to verify
	 * @throws	CertificateException	When something is wrong with the certificate
	 */
	private static void verifyCert(X509Certificate servCert) throws CertificateException{
		boolean ca = false;
		boolean valid = false;
		
		if (servCert == null)
			throw new IllegalArgumentException("Server Certificate Not Found");
		
		if (!CACERT.equals(servCert)){
			try{
				servCert.verify(CACERT.getPublicKey());
				ca = true;
			} catch (Exception e) {
				Output.error("Server Certificate not Trusted");
			}
		}
		
		try {
			servCert.checkValidity();
			valid = true;
		} catch (Exception e) {
			Output.error("Server Certificate is expired");
		}
		VALID = ca && valid;
	}
	
	/**
	 * Close connection and exit the program
	 * @param	exitCd	Exit code
	 */
	private static void close(int exitCd){
		if (exitCd == 1){
			String msg = "Server identity not verified";
			Output.error(msg);
		}
		if (exitCd == 2) {
			String msg = "Data received is corrupted";
			Output.error(msg);
		}
		try {
            SIN.close();
            SOUT.close();
			SOCKET.close();
			Output.info("Connection with server closed");
			
			if (exitCd != 1) {
				System.exit(1);
			} else {
				System.exit(0);
			}
		} catch (IOException e){
			Output.error("Unexpected Exception " + e.getMessage());
		}
	}
}
