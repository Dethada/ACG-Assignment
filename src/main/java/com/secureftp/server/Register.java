package com.secureftp.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import com.secureftp.common.BCryptUtil;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;

public class Register {
    public static void main(String[] args) throws Exception {
        Options options = new Options();

        Option user = new Option("u", "user", true, "Username of target user");
        user.setRequired(true);
        options.addOption(user);

        Option auth = new Option("p", "path", true, "Authorization file path");
        auth.setRequired(true);
        options.addOption(auth);

        Option add = new Option("a", "add", false, "Add user");
        add.setRequired(false);
        options.addOption(add);

        Option del = new Option("d", "delete", false, "Delete user");
        del.setRequired(false);
        options.addOption(del);

        Option help = new Option("h", "help", false, "Prints help message");
        help.setRequired(false);
        options.addOption(help);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmdargs;

        String username = "";
        String authfile = "";
        try {
            cmdargs = parser.parse(options, args);

            if (cmdargs.hasOption("h")) {
                exit(formatter, options, 0);
            }

            if ((cmdargs.hasOption("a") && cmdargs.hasOption("d"))
                    || (!cmdargs.hasOption("a") && !cmdargs.hasOption("d"))) {
                exit(formatter, options, 0);
            }

            if (cmdargs.hasOption("u")) {
                username = cmdargs.getOptionValue("u");
                if (!username.matches("^[A-z\\d]{1,20}$")) {
                    System.out.println("Username must be alphanumeric and between 1 to 20 characters long.");
                    System.exit(0);
                }
            }

            if (cmdargs.hasOption("p")) {
                authfile = cmdargs.getOptionValue("p");
            }

            if (cmdargs.hasOption("a")) {
                if (userExist(username, authfile)) {
                    System.out.println("User already exists");
                    System.exit(0);
                }
                String line = username + ":"
                        + BCryptUtil.hashPassword(new String(System.console().readPassword("Password: ")));
                try {
                    final Path path = Paths.get(authfile);
                    Files.write(path, Arrays.asList(line), StandardCharsets.UTF_8,
                            Files.exists(path) ? StandardOpenOption.APPEND : StandardOpenOption.CREATE);
                } catch (final IOException ioe) {
                    System.out.println("Failed to add user.");
                    System.exit(1);
                }
            } else if (cmdargs.hasOption("d")) {
                File file = new File(authfile);
                String targetuser = username;
                List<String> lines = FileUtils.readLines(file);
                List<String> updatedLines = lines.stream().filter(s -> !s.split(":")[0].equals(targetuser))
                        .collect(Collectors.toList());
                FileUtils.writeLines(file, updatedLines, false);
            }
        } catch (ParseException e) {
            System.out.println(e.getMessage() + '\n');
            exit(formatter, options, 1);
        }
    }

    /**
     * Print help message and exit
     * 
     * @param formatter HelpFormatter
     * @param options   Options
     * @param exitcd    Program Exit code
     */
    private static void exit(HelpFormatter formatter, Options options, int exitcd) {
        System.out.println("Secure FTP Client\n");
        formatter.printHelp("java -jar Client.jar <options>", options);
        System.exit(exitcd);
    }

    /**
     * Check if user exist in auth file
     * 
     * @param user     Username of target user
     * @param authfile Auth file path
     * @return true if user exists, else return false
     */
    private static boolean userExist(String user, String authfile) {
        try (BufferedReader br = new BufferedReader(new FileReader(authfile))) {
            for (String line; (line = br.readLine()) != null;) {
                String[] tmp = line.split(":");
                if (tmp[0].equals(user)) {
                    return true;
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }
}