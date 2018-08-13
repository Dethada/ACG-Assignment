package com.secureftp.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

import com.secureftp.common.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class Server {

	private Certificate CERT;
	private KeyPair KEYPAIR;
	private static Logger LOG;

	public static void main(String[] args) throws Exception {
		Options options = new Options();

		String conf_path = "SecureFTP.conf";
		Option conf = new Option("c", "conf", true, "Configuration file path");
		conf.setRequired(true);
		options.addOption(conf);

		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);

		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
		CommandLine cmdargs;

		int port = 21;
		int backloglimit = 50;
		InetAddress bindaddr = InetAddress.getByName("0.0.0.0");
		String keyStore, keyStorePass, aliasName, aliasPass, bannerpath, banner, defaultdir, authfile;
		keyStore = keyStorePass = aliasName = aliasPass = bannerpath = banner = defaultdir = authfile = "";
		try {
			cmdargs = parser.parse(options, args);
			LOG = new Logger();
			Properties prop = new Properties();
			if (cmdargs.hasOption("c")) {
				conf_path = cmdargs.getOptionValue("c");
			}
			InputStream inputStream = new FileInputStream(conf_path);
			prop.load(inputStream);

			try {
				port = Integer.parseInt(prop.getProperty("PORT"));
			} catch (NumberFormatException e) {
				System.out.println("Invalid Port number, please check the configuration file.");
				System.exit(0);
			}
			try {
				backloglimit = Integer.parseInt(prop.getProperty("BACKLOG_LIMIT"));
			} catch (NumberFormatException e) {
				System.out.println("Invalid Connection limit, please check the configuration file.");
				System.exit(0);
			}
			String addr = prop.getProperty("BIND_ADDR");
			if (!addr.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}")) {
				System.out.println("Invalid IP address, please check the configuration file.");
				System.exit(1);
			}
			bindaddr = InetAddress.getByName(addr);
			keyStore = prop.getProperty("KEYSTORE");
			keyStorePass = prop.getProperty("KEYSTORE_PASS");
			aliasName = prop.getProperty("ALIASNAME");
			aliasPass = prop.getProperty("ALIAS_PASS");
			bannerpath = prop.getProperty("BANNER");
			defaultdir = prop.getProperty("DEFAULT_DIR");
			authfile = prop.getProperty("AUTH_FILE");
			File f = new File(defaultdir);
			if (!(f.exists() && f.isDirectory() && f.isAbsolute())) {
				System.out.println("Invalid default directory set, please check the configuration file.");
				System.exit(1);
			}
			f = new File(authfile);
			if (!(f.exists() && f.isFile())) {
				System.out.println("Invalid Authorization file set, please check the configuration file.");
				System.exit(1);
			}

			if (cmdargs.hasOption("h")) {
				System.out.println("Secure FTP Server\n");
				formatter.printHelp("java -jar SecureFTP-Server.jar <options>", options);
				System.exit(0);
			}
			try {
				banner = readFile(bannerpath, StandardCharsets.UTF_8);
			} catch (IOException e) {
				System.out.println("Invalid banner file.");
				System.exit(1);
			}

		} catch (ParseException e) {
			System.out.println(e.getMessage() + "\n\nSecure FTP Server\n");
			formatter.printHelp("java -jar SecureFTP-Server.jar <options>", options);
			System.exit(1);
		} catch (FileNotFoundException e) {
			System.out.println("Invalid server configuration file.");
			System.exit(1);
		}

		try {
			new Server(keyStore, keyStorePass, aliasName, aliasPass).start(bindaddr, port, backloglimit, banner,
					defaultdir, authfile);
		} catch (Exception e) {
			System.out.println("An unexpected Error Occured\n" + e.getMessage());
		}

	}

	/**
	 * Prepare Server for connection
	 * 
	 * @param keyStorePath     Path of keystore where sever private key is located
	 * @param keyStorePassword Password to keystore where server private key is
	 *                         located
	 * @param aliasName        Alias of server private key
	 * @param aliasPassword    Password of the alias of server private key
	 * @throws UnrecoverableKeyException When key cannot be retrieved
	 * @throws FileNotFoundException     When file cannot be found
	 * @throws KeyStoreException         When something is wrong with the keystore
	 * @param IOException              When file cant be read
	 * @param BoSuchAlgorithnException When algorithm is not found
	 * @param CertificateException     When something is wrong with the certificate
	 */
	private Server(String keyStorePath, String keyStorePassword, String aliasName, String aliasPassword)
			throws UnrecoverableKeyException, FileNotFoundException, KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		// Load keystore using PKCS#12
		FileInputStream readKeyStore = new FileInputStream(keyStorePath);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(readKeyStore, keyStorePassword.toCharArray());

		// Get private key of server from keystore
		Key key = keyStore.getKey(aliasName, aliasPassword.toCharArray());

		if (key instanceof PrivateKey) {
			CERT = keyStore.getCertificate(aliasName);
			PublicKey pubkey = CERT.getPublicKey();
			KEYPAIR = new KeyPair(pubkey, (PrivateKey) key);
		} else {
			throw new UnrecoverableKeyException("Unable to obtain private key");
		}
	}

	/**
	 * Listen for client connections
	 * 
	 * @param bindaddr     IP address for server to bind to
	 * @param port         Port for server to listen on
	 * @param backloglimit Connection request queue limit
	 * @param banner       Banner to send the client upon connection
	 * @param defaultdir   Absolute path to Default directory
	 * @throws CertificateException When something is wrong with the certificate
	 */
	private void start(InetAddress bindaddr, int port, int backloglimit, String banner, String defaultdir,
			String authfile) throws CertificateException {
		ServerSocket sock = null;
		try {
			sock = new ServerSocket(port, backloglimit);
			LOG.info("Listening for connections on " + bindaddr.getHostAddress() + ":" + port);
			while (true) {
				new Connection(sock.accept(), CERT, KEYPAIR, banner, defaultdir, authfile, LOG).start();
			}
		} catch (IOException e) {
			LOG.error("An error occurred");
		}

	}

	/**
	 * Reads a text file into string
	 * 
	 * @param path     Path of the text file
	 * @param encoding Encoding of the text file
	 * @return a String with all the text in the text file.
	 */
	private static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}
}
