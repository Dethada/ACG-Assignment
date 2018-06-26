/***************************************************************
 *
 * A Simple One-Way Chat Program based on DH Key Exchange
 *
 * Singapore Polytechnic
 *
 ***************************************************************/

import java.io.*;
import java.net.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import sun.misc.*;

/*
 *		myServer.java
 *
 *		This is a simple one-way chat application,
 *      using a KeyAgreement to encrypt everything sent
 *		between a client and server.
 *
 *	    Usage: java myServer 9000
 *
 */
public class myServer {

/*
 *
 *	Static variables for 1024 bit Diffie-Hellman algorithm.
 *
 *	This is required to have matching moduli between client
 *	and server. The values are unimport, they simply must match.
 *	Ideally, everyone would agree on standard moduli, like SKIP,
 *	the Simple Key management for Internet Protocols spec.
 *
 *	For more details, please visit http://www.skip.org
 */

  private static final byte SKIP_1024_MODULUS_BYTES[] = {
    (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
    (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
    (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
    (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
    (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
    (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
    (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
    (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
    (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
    (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
    (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
    (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
    (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
    (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
    (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
    (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
    (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
    (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
    (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
    (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
    (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
    (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
    (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
    (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
    (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
    (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
    (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
    (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
    (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
    (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
    (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
    (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
  };

  /**
   *	Transform the representation above to a BigInteger.
   */
  private static final BigInteger MODULUS = new BigInteger
  (1,SKIP_1024_MODULUS_BYTES);

  /**
   *	The Base we're going to use is 2, as defined in SKIP.
   */
  private static final BigInteger BASE = BigInteger.valueOf(2);

  /**
   *	This wraps the parameters above into one object.
   */
  private static final DHParameterSpec PARAMETER_SPEC =
  new DHParameterSpec(MODULUS,BASE);

  public static String asHex (byte buf[]) {

  //Obtain a StringBuffer object
      StringBuffer strbuf = new StringBuffer(buf.length * 2);
      int i;

      for (i = 0; i < buf.length; i++) {
          if (((int) buf[i] & 0xff) < 0x10)
             strbuf.append("0");
             strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
      }
      // Return result string in Hexadecimal format
     return strbuf.toString();
  }

  public static void main (String[] args) throws Exception {

	if (args.length != 1) {
      System.err.println("Usage: java myServer port");
      System.exit(1);
    }

    int port = Integer.parseInt(args[0]);

    // Create a public key pair.
    // This will take a while: 5-15 seconds.
    System.out.println("Generating a Diffie-Hellman KeyPair...");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
    kpg.initialize(PARAMETER_SPEC);
    KeyPair keyPair = kpg.genKeyPair();

    ServerSocket ss = new ServerSocket (port);

    // Open a port and wait for a connection
    System.out.println("Listening on port " + port + "...");

    Socket socket = ss.accept();
    DataOutputStream out = new DataOutputStream(socket.getOutputStream());

    // Print server and client's IP addresses
    System.out.println("Server's IP address:" + socket.getLocalAddress().toString());
    System.out.println("Client's IP address:" + socket.getInetAddress().toString());

    // Send my public key
    byte[] keyBytes = keyPair.getPublic().getEncoded();
    out.writeInt(keyBytes.length);
    out.write(keyBytes);
    System.out.println("\nSending the server's public key.\n" + asHex(keyBytes) +"\n");

    DataInputStream in = new DataInputStream(socket.getInputStream());
    keyBytes = new byte[in.readInt()];
    in.readFully(keyBytes);

    KeyFactory kf = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
    PublicKey clientPublicKey = kf.generatePublic(x509Spec);

    // Receive the client's public key
    System.out.println("Receiving client's public key.\n" + asHex(clientPublicKey.getEncoded()) + "\n");

    // Perform the KeyAgreement
    System.out.println("Performing the KeyAgreement (Server)...");
    KeyAgreement ka = KeyAgreement.getInstance("DH");
    ka.init(keyPair.getPrivate());
    ka.doPhase(clientPublicKey,true);

    // Create and send the IVParameterSpec
    byte[] iv = new byte[8];
    SecureRandom sr = new SecureRandom();
    sr.nextBytes(iv);
    out.write(iv);

    // Generate the bytes we'll use to create TripleDES key
    byte[] sessionKeyBytes = ka.generateSecret();

    // Create the session key
    SecretKeyFactory skf = SecretKeyFactory.getInstance("TripleDES");
    DESedeKeySpec tripleDesSpec = new DESedeKeySpec(sessionKeyBytes);
    SecretKey sessionKey = skf.generateSecret(tripleDesSpec);
    System.out.println("Our session key: " + asHex(sessionKey.getEncoded()) + "\n");

    // Create the CipherStream to be used
    System.out.println("Creating the CipherStream...");
    Cipher decrypter = Cipher.getInstance("TripleDES/CFB8/NoPadding");
    IvParameterSpec spec = new IvParameterSpec(iv);
    decrypter.init(Cipher.DECRYPT_MODE, sessionKey, spec);
    CipherInputStream cipherIn = new CipherInputStream(socket.getInputStream(), decrypter);

    // Print everything received through the CipherStream
    int theCharacter=0;
    theCharacter = cipherIn.read();
    while (theCharacter != -1) {
      System.out.print((char)theCharacter);
      theCharacter = cipherIn.read();
    }

    cipherIn.close();
    in.close();
    out.close();
    socket.close();
  }

} // End of program
