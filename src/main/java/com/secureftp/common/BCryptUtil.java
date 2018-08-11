package com.secureftp.common;

import org.mindrot.jbcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

// https://gist.github.com/craSH/5217757
public class BCryptUtil {
    // Define the BCrypt workload to use when generating password hashes. 10-31 is a
    // valid value.
    private static int workload = 12;

    /**
     * This method can be used to generate a string representing an account password
     * suitable for storing in a database. It will be an OpenBSD-style crypt(3)
     * formatted hash string of length=60 The bcrypt workload is specified in the
     * above static variable, a value from 10 to 31. A workload of 12 is a very
     * reasonable safe default as of 2013. This automatically handles secure 128-bit
     * salt generation and storage within the hash.
     *
     * @param password_plaintext The account's plaintext password as provided during
     *                           account creation, or when changing an account's
     *                           password.
     * @return String - a string of length 60 that is the bcrypt hashed password in
     *         crypt(3) format.
     */
    public static String hashPassword(String password_plaintext) {
        String salt = BCrypt.gensalt(workload);
        String hashed_password = BCrypt.hashpw(sha256hash(password_plaintext), salt);

        return (hashed_password);
    }

    /**
     * This method can be used to verify a computed hash from a plaintext (e.g.
     * during a login request) with that of a stored hash from a database. The
     * password hash from the database must be passed as the second variable. Hashed
     * with sha256 first to prevent passwords > 72 characters from being truncated.
     *
     * @param password_plaintext The account's plaintext password, as provided
     *                           during a login request
     * @param stored_hash        The account's stored password hash, retrieved from
     *                           the authorization database
     * @return boolean - true if the password matches the password of the stored
     *         hash, false otherwise
     */
    public static boolean checkPassword(String password_plaintext, String stored_hash) {
        if (null == stored_hash || !stored_hash.startsWith("$2a$"))
            throw new java.lang.IllegalArgumentException("Invalid hash provided for comparison");

        return BCrypt.checkpw(sha256hash(password_plaintext), stored_hash);
    }

    /**
     * This method returns the sha256 hash of a String.
     *
     * @param plaintext The account's plaintext password as provided during account
     *                  creation, or when changing an account's password.
     * @return String - sha256 hash of the plaintext in hex string format, length 64
     */
    private static String sha256hash(String plaintext) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return bytesToHex(digest.digest(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * This method converts bytes to hex string
     *
     * @param bytes The bytes to be converted to hex string
     * @return String - hex string of the bytes
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte byt : bytes)
            result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}