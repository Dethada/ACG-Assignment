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
	
	
	public static void main (String[] args) throws Exception { 
		Options options = new Options();

		String conf_path = "SecureFTP.conf";
		Option conf = new Option("c", "conf", true, "Configuration file path");
		conf.setRequired(true);
		options.addOption(conf);
		
		Option verb = new Option("v", "verbose", false, "Verbose Output");
		verb.setRequired(false);
		options.addOption(verb);
		
		Option help = new Option("h", "help", false, "Prints help message");
		help.setRequired(false);
		options.addOption(help);
		
		CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
		CommandLine cmdargs;
		
		int port = 21;
		InetAddress bindaddr = InetAddress.getByName("0.0.0.0");
		String keyStore, keyStorePass, aliasName, aliasPass, bannerpath, banner, defaultdir;
		keyStore = keyStorePass = aliasName = aliasPass = bannerpath = banner = defaultdir = "";
		try {
            cmdargs = parser.parse(options, args);
			LOG = new Logger(cmdargs.hasOption("v"));
			Properties prop = new Properties();
			if (cmdargs.hasOption("c")) {
				conf_path = cmdargs.getOptionValue("c");
			}
			InputStream inputStream = new FileInputStream(conf_path);;
			prop.load(inputStream);

			try {
				port = Integer.parseInt(prop.getProperty("PORT"));
			} catch (NumberFormatException e) {
				LOG.error("Invalid Port number, please check the configuration file.");
				System.exit(0);
			}
			String addr = prop.getProperty("BIND_ADDR");
			if (!addr.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}")){
				LOG.error("Invalid IP address, please check the configuration file.");
				System.exit(1);
			}
			bindaddr = InetAddress.getByName(addr);
			keyStore = prop.getProperty("KEYSTORE");
			keyStorePass = prop.getProperty("KEYSTORE_PASS");
			aliasName = prop.getProperty("ALIASNAME");
			aliasPass = prop.getProperty("ALIAS_PASS");
			bannerpath = prop.getProperty("BANNER");
			defaultdir = prop.getProperty("DEFAULT_DIR");
			File f = new File(defaultdir);
			if (!(f.exists() && f.isDirectory()) || !defaultdir.startsWith("/")) {
				LOG.error("Invalid default directory set, please check the configuration file.");
				System.exit(1);
			}
			
			if (cmdargs.hasOption("h")){
				System.out.println("Secure FTP Server\n");
				formatter.printHelp("java -jar Server.jar <options>", options);
				System.exit(0);
			}
			try {
				banner = readFile(bannerpath, StandardCharsets.UTF_8);
			} catch (IOException e) {
				LOG.error("Invalid banner file.");
				System.exit(1);
			}
			
        } catch (ParseException e) {
			LOG.error(e.getMessage() + "\nUsage: java Server <options>\nUse -h to display help");
            System.exit(1);
        } catch(FileNotFoundException e) {
			LOG.error("Invalid server configuration file.");
			System.exit(1);
		}
		LOG.verbose("Server Startup Initiated");
		
		try {
			new Server(keyStore, keyStorePass, aliasName, aliasPass).start(bindaddr, port, banner, defaultdir);
		} catch (Exception e){
			LOG.error("An unexpected Error Occured\n", e);
		}
		
	}
	
	/**
	 * Prepare Server for connection
	 * @param	keyStorePath				Path of keystore where sever private key is located
	 * @param	keyStorePassword			Password to keystore where server private key is located
	 * @param	aliasName					Alias of server private key
	 * @param	aliasPassword				Password of the alias of server private key
	 * @throws	UnrecoverableKeyException	When key cannot be retrieved
	 * @throws	FileNotFoundException		When file cannot be found
	 * @throws	KeyStoreException			When something is wrong with the keystore
	 * @param	IOException					When file cant be read
	 * @param	BoSuchAlgorithnException	When algorithm is not found
	 * @param	CertificateException		When something is wrong with the certificate
	 */
	private Server(String keyStorePath, String keyStorePassword, String aliasName, String aliasPassword) throws UnrecoverableKeyException, FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
		// Load keystore using PKCS#12
		FileInputStream readKeyStore = new FileInputStream(keyStorePath);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(readKeyStore, keyStorePassword.toCharArray());
		
		// Get private key of server from keystore
		Key key = keyStore.getKey(aliasName, aliasPassword.toCharArray());

		if (key instanceof PrivateKey){
			CERT = keyStore.getCertificate(aliasName);
			PublicKey pubkey = CERT.getPublicKey();
			KEYPAIR = new KeyPair(pubkey, (PrivateKey) key);
		} else {
			throw new UnrecoverableKeyException("Unable to obtain private key");
		}
	}
	
	/**
	 * Listen for client connections
 	 * @param	bindaddr				IP address for server to bind to
	 * @param	port					Port for server to listen on
	 * @param	maxcon					Maximum number of connections the server allows
	 * @param	banner					Banner to send the client upon connection
	 * @param	defaultdir				Absolute path to Default directory
	 * @throws	CertificateException	When something is wrong with the certificate
	 */
	private void start(InetAddress bindaddr, int port, String banner, String defaultdir) throws CertificateException {
		ServerSocket sock = null;
		try{
			sock = new ServerSocket(port);
			LOG.info("Server Startup successful");
			LOG.info("Listening for connections on " + bindaddr.getHostAddress() + ":" + port);
			while (true) {
				new Connection(sock.accept(), CERT, KEYPAIR, banner, defaultdir, LOG).start();
			}
		} catch (IOException e){
			LOG.error("An error occurred");
			LOG.info("Server shutting down....");
		}
	
	}

	private static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}
}
