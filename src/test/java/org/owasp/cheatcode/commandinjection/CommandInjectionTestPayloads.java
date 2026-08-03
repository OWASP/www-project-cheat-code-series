package org.owasp.cheatcode.commandinjection;

/**
 * Contains constants for command injection test payloads used in security testing.
 */
public final class CommandInjectionTestPayloads {
    private CommandInjectionTestPayloads() {
        // Prevent instantiation
    }

    // Command chaining attacks
    public static final String BASIC_CHAINING = " & ";
    public static final String LOGICAL_AND = " && ";
    public static final String LOGICAL_OR = " || ";
    public static final String COMMAND_SEPARATOR = "; ";

    // Pipe operations
    public static final String BASIC_PIPE = " | ";
    public static final String STDERR_PIPE = " |& ";

    // Redirection attacks
    public static final String OUTPUT_REDIRECT = " > evil.txt";
    public static final String APPEND_REDIRECT = " >> evil.txt";
    public static final String INPUT_REDIRECT = " < C:\\Windows\\System32\\drivers\\etc\\hosts";
    public static final String ERROR_REDIRECT = " 2> error.log";

    // Subcommand execution
    public static final String COMMAND_SUBSTITUTION_DOLLAR = "; $(whoami)";
    public static final String COMMAND_SUBSTITUTION_BACKTICK = "; `whoami`";
    public static final String WINDOWS_FOR_LOOP = " & for /f %i in ('whoami') do echo %i";

    // Windows-specific attacks
    public static final String WINDOWS_DIR = " & dir";
    public static final String WINDOWS_NET_USER = " && net user";
    public static final String WINDOWS_FINDSTR = " | findstr \"admin\"";
    public static final String WINDOWS_CURRENT_DIR = " & echo %CD%";
    public static final String WINDOWS_USERNAME = " & echo %USERNAME%";

    // Encoding/obfuscation attempts
    public static final String URL_ENCODED_AND = "%26%26";
    public static final String URL_ENCODED_SEMICOLON = "%3B";
    public static final String NEWLINE_INJECTION = "\n";
    public static final String CRLF_INJECTION = "\r\n";

    // Multi-command attempts
    public static final String MULTI_ECHO = "; echo injection1 && echo injection2";
    public static final String MULTIPLE_ENV_VARS = " & echo %CD% & echo %USERNAME%";
    public static final String TIMING_ATTACK = " && timeout 1 >nul";

    // File system exploration
    public static final String ROOT_DIR_LISTING = " & dir C:\\";
    public static final String HOSTS_FILE_READ = " & type C:\\Windows\\System32\\drivers\\etc\\hosts";

    // Common injection payloads array for easy iteration
    public static final String[] ALL_PAYLOADS = {
        BASIC_CHAINING,
        LOGICAL_AND,
        LOGICAL_OR,
        COMMAND_SEPARATOR,
        BASIC_PIPE,
        STDERR_PIPE,
        OUTPUT_REDIRECT,
        APPEND_REDIRECT,
        INPUT_REDIRECT,
        ERROR_REDIRECT,
        COMMAND_SUBSTITUTION_DOLLAR,
        COMMAND_SUBSTITUTION_BACKTICK,
        WINDOWS_FOR_LOOP,
        WINDOWS_DIR,
        WINDOWS_NET_USER,
        WINDOWS_FINDSTR,
        WINDOWS_CURRENT_DIR,
        WINDOWS_USERNAME,
        URL_ENCODED_AND,
        URL_ENCODED_SEMICOLON,
        NEWLINE_INJECTION,
        CRLF_INJECTION,
        MULTI_ECHO,
        MULTIPLE_ENV_VARS,
        TIMING_ATTACK,
        ROOT_DIR_LISTING,
        HOSTS_FILE_READ
    };
}