package com.secureftp.server;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;

import com.secureftp.common.BCryptUtil;
import com.secureftp.common.FileTransfer;
import com.secureftp.common.Logger;
import com.secureftp.common.Login;
import com.secureftp.common.UserLogger;
import com.secureftp.common.Utils;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Connection extends Thread implements Runnable {

	private Socket SOCKET;
	private java.security.cert.Certificate SERVERCERT;
	private Logger LOG;
	private UserLogger USERLOG;
	private String REMOTE;
	private KeyPair KEYPAIR;
	private String BANNER;
	private String DEFAULTDIR;
	private String CWD;
	private ObjectOutputStream SOUT;
	private ObjectInputStream SIN;
	private String AUTHFILE;

	/**
	 * @param SOCKET     Socket to connect with client
	 * @param SERVERCERT Server Certificate
	 * @param KEYPAIR    Server Public Private keypair
	 * @param BANNER     Certificate Authority Certificate
	 * @param DEFAULTDIR Default directory of the ftp program
	 * @param LOG        Logger to print information to screen
	 * @throws CertificateException  When something is wrong with the certificate
	 * @throws FileNotFoundException When file cannot be found
	 * @param IOException When file cant be read
	 */
	public Connection(Socket SOCKET, java.security.cert.Certificate SERVERCERT, KeyPair KEYPAIR, String BANNER,
			String DEFAULTDIR, String AUTHFILE, Logger LOG)
			throws CertificateException, FileNotFoundException, IOException {
		this.SOCKET = SOCKET;
		this.SERVERCERT = SERVERCERT;
		this.KEYPAIR = KEYPAIR;
		this.BANNER = BANNER;
		this.DEFAULTDIR = DEFAULTDIR;
		this.CWD = DEFAULTDIR;
		this.AUTHFILE = AUTHFILE;
		this.LOG = LOG;
		this.REMOTE = SOCKET.getRemoteSocketAddress().toString().substring(1);
	}

	/**
	 * Starts running thread to handle client connection
	 */
	public void run() {
		Security.addProvider(new BouncyCastleProvider());
		try {
			Certificate cert = Certificate.getInstance(ASN1TaggedObject.fromByteArray(SERVERCERT.getEncoded()));

			// Start TLS handshake
			TlsServerProtocol proto = new TlsServerProtocol(SOCKET.getInputStream(), SOCKET.getOutputStream(),
					new SecureRandom());

			DefaultTlsServer tlsserver = new DefaultTlsServer() {

				// Set maximum protocol version version
				protected ProtocolVersion getMaximumVersion() {
					return ProtocolVersion.TLSv12;
				}

				// Get TLS Signer Credentials to use for TLS Connection
				protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
					SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) TlsUtils
							.getDefaultRSASignatureAlgorithms().get(0);
					return new DefaultTlsSignerCredentials((TlsContext) context,
							new org.bouncycastle.crypto.tls.Certificate(new Certificate[] { cert }),
							PrivateKeyFactory.createKey(KEYPAIR.getPrivate().getEncoded()), signatureAndHashAlgorithm);
				}
			};
			proto.accept(tlsserver);

			// Use the new socket streams to communicate with the client securely
			SOUT = new ObjectOutputStream(proto.getOutputStream());
			SIN = new ObjectInputStream(proto.getInputStream());
			SOUT.flush();

			// LOG.verbose("Connection established with " + REMOTE);

			sendReply(BANNER);

			// authenticate user
			Login login = (Login) SIN.readObject();
			if (verifyUser(login)) {
				LOG.info("Login successful with user: " + login.getUsername());
				sendOk("Login successful");
				USERLOG = new UserLogger(login.getUsername());
			} else {
				LOG.info("Login failed with user: " + login.getUsername());
				sendError("Login failed");
				close();
				return;
			}

			String cmd = "";
			while (true) {
				cmd = SIN.readUTF().trim();

				// parse commands
				if (cmd.equals("ls")) {
					sendReply(Utils.listFilesAndFolders(CWD));
				} else if (cmd.startsWith("ls ")) {
					String[] tmp = cmd.split("\\s");
					if (tmp[1].startsWith("/")) {
						try {
							sendReply(Utils.listFilesAndFolders(tmp[1]));
						} catch (NullPointerException e) {
							sendError("Invalid directory");
						}
					} else {
						try {
							sendReply(Utils.listFilesAndFolders(CWD + "/" + tmp[1]));
						} catch (NullPointerException e) {
							sendError("Invalid directory");
						}
					}
				} else if (cmd.equals("cd")) {
					CWD = DEFAULTDIR;
					sendOk("Changed directory to " + DEFAULTDIR);
				} else if (cmd.startsWith("cd ")) {
					String[] tmp = cmd.split("\\s");
					String tmpDir = Utils.changeDir(CWD, tmp[1]);
					if (tmpDir != null) {
						CWD = tmpDir;
						sendOk("Changed directory to " + tmp[1]);
					} else {
						sendError("Invalid directory");
					}
				} else if (cmd.equals("get") || cmd.equals("put") || cmd.equals("rm") || cmd.equals("mkdir")) {
					sendError("Missing argument\n");
				} else if (cmd.startsWith("get ")) {
					String[] tmp = cmd.split("\\s");
					try {
						if (tmp[1].startsWith("/")) {
							FileTransfer.sendFile(tmp[1], SOUT);
							USERLOG.info("Downloaded file " + tmp[1]);
						} else {
							FileTransfer.sendFile(CWD + "/" + tmp[1], SOUT);
							USERLOG.info("Downloaded file " + CWD + "/" + tmp[1]);
						}

					} catch (IOException e) {
						USERLOG.error("Send file " + tmp[1] + " failed", e);
						sendError("Exception occured when sending file\n");
					}
				} else if (cmd.equals("SFO")) {
					try {
						String fname = FileTransfer.recvFile(SIN, CWD);
						if (fname != null) {
							USERLOG.info("Recieved " + fname);
						} else {
							USERLOG.error("File integrity compromised during transfer.");
						}
					} catch (IOException e) {
						sendReply("Error occured when recieving file.");
						USERLOG.error("Error when recieving file", e);
					}
				} else if (cmd.startsWith("rm ")) {
					String[] tmp = cmd.split("\\s");
					if (tmp[1].startsWith("/")) {
						File f = new File(tmp[1]);
						if (f.exists()) {
							FileUtils.deleteQuietly(f);
							sendReply("File deleted");
							USERLOG.info("Deleted " + tmp[1]);
						} else {
							sendError("Cannot remove " + tmp[1] + "No such file or directory");
						}
					} else {
						File f = new File(CWD + "/" + tmp[1]);
						if (f.exists()) {
							FileUtils.deleteQuietly(f);
							sendReply("File deleted");
							USERLOG.info("Deleted " + tmp[1]);
						} else {
							sendError("Cannot remove " + tmp[1] + "No such file or directory");
						}
					}
				} else if (cmd.startsWith("mkdir ")) {
					String[] tmp = cmd.split("\\s");
					if (tmp[1].startsWith("/")) {
						File f = new File(tmp[1]);
						if (!f.exists()) {
							if (f.mkdir()) {
								sendReply("Directory created.");
								USERLOG.info("Created directory " + tmp[1]);
							} else {
								sendError("Failed to create " + tmp[1]);
							}
						} else {
							sendError("Cannot create " + tmp[1] + "file or directory exists");
						}
					} else {
						File f = new File(CWD + "/" + tmp[1]);
						if (!f.exists()) {
							if (f.mkdir()) {
								sendReply("Directory created.");
								USERLOG.info("Created directory " + tmp[1]);
								sendError("Failed to create " + tmp[1]);
							}
						} else {
							sendError("Cannot create " + tmp[1] + "file or directory exists");
						}
					}
				} else if (cmd.equals("pwd")) {
					sendReply(CWD);
				} else if (cmd.equals("whoami")) {
					sendReply(System.getProperty("user.name"));
				} else if (cmd.equals("help") || cmd.equals("?")) {
					sendReply(
							"Commands available\nls\t- list files\ncd\t- change directory\npwd\t- print current working directory\n"
									+ "get\t- download a file\nput\t- upload a file\nrm\t- delete a file or directory\nmkdir\t- create a directory\n"
									+ "whoami\t- Get the user the server is running as\nlls\t- local list files\nlcd\t- local change directory\n"
									+ "lpwd\t- local print current working directory\nexit\t- Close connection and quit\n");
				} else if (cmd.equals("exit") || cmd.equals("quit") || cmd.equals("bye")) {
					break;
				} else {
					sendError("Invalid Command. Type help to show available commands.\n");
				}
			}
			USERLOG.info("Connection closed.");
			// Closes Connection
			close();
		} catch (SocketException e) {
			USERLOG.info("Client Closed Connection");
			close();
		} catch (EOFException e) {
		} catch (Exception e) {
			LOG.error("Unexpected Exception", e);
		}
	}

	/**
	 * Sends a plain message to client
	 * 
	 * @param msg Message to be sent to the client
	 * @return true if message sent successfully, false if it failed.
	 */
	private boolean sendReply(String msg) {
		try {
			SOUT.writeUTF(msg);
			SOUT.flush();
			return true;
		} catch (IOException e) {
			LOG.error("Can't connect to client", e);
			return false;
		}
	}

	/**
	 * Sends a error message to client
	 * 
	 * @param msg Message to be sent to the client
	 * @return true if message sent successfully, false if it failed.
	 */
	private boolean sendError(String msg) {
		try {
			SOUT.writeUTF(Utils.ANSI_RED + msg + Utils.ANSI_RESET);
			SOUT.flush();
			return true;
		} catch (IOException e) {
			LOG.error("Can't connect to client", e);
			return false;
		}
	}

	/**
	 * Sends a success message to client
	 * 
	 * @param msg Message to be sent to the client
	 * @return true if message sent successfully, false if it failed.
	 */
	private boolean sendOk(String msg) {
		try {
			SOUT.writeUTF(Utils.ANSI_GREEN + msg + Utils.ANSI_RESET);
			SOUT.flush();
			return true;
		} catch (IOException e) {
			LOG.error("Can't connect to client", e);
			return false;
		}
	}

	/**
	 * Verify user credentials
	 * 
	 * @param login Login object containing username and password
	 * @return true if username and password are valid, else return false
	 */
	private boolean verifyUser(Login login) {
		String username = login.getUsername();
		String password = login.getPassword();
		try (BufferedReader br = new BufferedReader(new FileReader(AUTHFILE))) {
			for (String line; (line = br.readLine()) != null;) {
				String[] tmp = line.split(":");
				if (tmp[0].equals(username)) {
					return BCryptUtil.checkPassword(password, tmp[1]);
				}
			}
		} catch (IOException e) {
			return false;
		}
		return false;
	}

	/**
	 * Closes connection with client
	 */
	private void close() {
		try {
			SOUT.close();
			SIN.close();
			SOCKET.close();
		} catch (IOException e) {
			LOG.error("An unexpected error occurred : ", e);
		}
	}
}