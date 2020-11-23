use std::fmt::{Display, Formatter, Write};
use std::str::FromStr;

use anyhow::Result;

#[derive(Copy, Clone, Debug)]
pub enum Command {
    /// APOP is used to do digest auth
    ///
    /// # Restrictions
    ///
    /// Only be given in the AUTHORIZATION stqaate after the POP3 greeting or
    /// after an unsuccessful USER or PASS command
    ///
    /// # Discussion
    ///
    /// Normally, each POP3 session starts with a USER/PASS
    /// exchange.  This results in a server/user-id specific
    /// password being sent in the clear onw the network.  For
    /// intermittent use of POP3, this may not introduce a sizable
    /// risk.  However, many POP3 client implementations connect to
    /// the POP3 server on a regular basis -- to check for new
    /// mail.  Further the interval of session initiation may be on
    /// the order of five minutes.  Hence, the risk of password
    /// capture is greatly enhanced.
    ///
    /// An alternate method of authentication is required which
    /// provides for both origin authentication and replay
    /// protection, but which does not involve sending a password
    /// in the clear over the network.  The APOP command provides
    /// this functionality.
    ///
    /// A POP3 server which implements the APOP command will
    /// include a timestamp in its banner greeting.  The syntax of
    /// the timestamp corresponds to the `msg-id' in [RFC822], and
    /// MUST be different each time the POP3 server issues a banner
    /// greeting.  For example, on a UNIX implementation in which a
    /// separate UNIX process is used for each instance of a POP3
    /// server, the syntax of the timestamp might be:
    ///
    /// <process-ID.clock@hostname>
    ///
    /// where `process-ID' is the decimal value of the process's
    /// PID, clock is the decimal value of the system clock, and
    /// hostname is the fully-qualified domain-name corresponding
    /// to the host where the POP3 server is running.
    ///
    /// The POP3 client makes note of this timestamp, and then
    /// issues the APOP command.  The `name' parameter has
    /// identical semantics to the `name' parameter of the USER
    /// command. The `digest' parameter is calculated by applying
    /// the MD5 algorithm [RFC1321] to a string consisting of the
    /// timestamp (including angle-brackets) followed by a shared
    /// secret.  This shared secret is a string known only to the
    /// POP3 client and server.  Great care should be taken to
    /// prevent unauthorized disclosure of the secret, as knowledge
    /// of the secret will allow any entity to successfully
    /// masquerade as the named user.  The `digest' parameter
    /// itself is a 16-octet value which is sent in hexadecimal
    /// format, using lower-case ASCII characters.
    ///
    /// When the POP3 server receives the APOP command, it verifies
    /// the digest provided.  If the digest is correct, the POP3
    /// server issues a positive response, and the POP3 session
    /// enters the TRANSACTION state.  Otherwise, a negative
    /// response is issued and the POP3 session remains in the
    /// AUTHORIZATION state.
    ///
    /// Note that as the length of the shared secret increases, so
    /// does the difficulty of deriving it.  As such, shared
    /// secrets should be long strings (considerably longer than
    /// the 8-character example shown below).
    ///
    /// # Syntax
    ///
    /// S: +OK POP3 server ready <process-id.clock@hostname>
    /// C: APOP <username> <digest of "<process-id.clock@hostname><password>">
    /// S: +OK [msg]
    ///
    /// # Examples
    ///
    /// S: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
    /// C: APOP mrose c4c9334bac560ecc979e58001b3e22fb
    /// S: +OK maildrop has 1 message (369 octets)
    ///
    ///  In this example, the shared  secret  is  the  string  `tan-
    ///  staaf'.  Hence, the MD5 algorithm is applied to the string
    ///
    ///     <1896.697170952@dbc.mtview.ca.us>tanstaaf
    ///
    ///  which produces a digest value of
    ///
    ///     c4c9334bac560ecc979e58001b3e22fb
    APOP,
    /// AUTH command indicates an authentication mechanism to the server.
    ///
    /// # Restrictions
    ///
    /// Only be given in the AUTHORIZATION state
    ///
    /// # Discussion
    ///
    /// The AUTH command indicates an authentication mechanism to
    /// the server.  If the server supports the requested
    /// authentication mechanism, it performs an authentication
    /// protocol exchange to authenticate and identify the user.
    /// Optionally, it also negotiates a protection mechanism for
    /// subsequent protocol interactions.  If the requested
    /// authentication mechanism is not supported, the server
    ///
    ///
    /// should reject the AUTH command by sending a negative
    /// response.
    ///
    /// The authentication protocol exchange consists of a series
    /// of server challenges and client answers that are specific
    /// to the authentication mechanism.  A server challenge,
    /// otherwise known as a ready response, is a line consisting
    /// of a "+" character followed by a single space and a BASE64
    /// encoded string.  The client answer consists of a line
    /// containing a BASE64 encoded string.  If the client wishes
    /// to cancel an authentication exchange, it should issue a
    /// line with a single "*".  If the server receives such an
    /// answer, it must reject the AUTH command by sending a
    /// negative response.
    ///
    /// A protection mechanism provides integrity and privacy
    /// protection to the protocol session.  If a protection
    /// mechanism is negotiated, it is applied to all subsequent
    /// data sent over the connection.  The protection mechanism
    /// takes effect immediately following the CRLF that concludes
    /// the authentication exchange for the client, and the CRLF of
    /// the positive response for the server.  Once the protection
    /// mechanism is in effect, the stream of command and response
    /// octets is processed into buffers of ciphertext.  Each
    /// buffer is transferred over the connection as a stream of
    /// octets prepended with a four octet field in network byte
    /// order that represents the length of the following data.
    /// The maximum ciphertext buffer length is defined by the
    /// protection mechanism.
    ///
    /// The server is not required to support any particular
    /// authentication mechanism, nor are authentication mechanisms
    /// required to support any protection mechanisms.  If an AUTH
    /// command fails with a negative response, the session remains
    /// in the AUTHORIZATION state and client may try another
    /// authentication mechanism by issuing another AUTH command,
    /// or may attempt to authenticate by using the USER/PASS or
    /// APOP commands.  In other words, the client may request
    /// authentication types in decreasing order of preference,
    /// with the USER/PASS or APOP command as a last resort.
    ///
    /// Should the client successfully complete the authentication
    /// exchange, the POP3 server issues a positive response and
    /// the POP3 session enters the TRANSACTION state.
    ///
    /// # Syntax
    ///
    /// ## List supported auth methods
    ///
    /// C: AUTH
    /// S: +OK <msg>
    /// S: <auth>
    /// S: .
    ///
    /// ## Check and start a specific auth
    ///
    /// C: AUTH <auth>
    /// S: <challenge>
    /// C: <response>
    /// S: +OK <msg>
    ///
    /// # Examples
    ///
    /// S: +OK POP3 server ready
    /// C: AUTH KERBEROS_V4
    /// S: + AmFYig==
    /// C: BAcAQU5EUkVXLkNNVS5FRFUAOCAsho84kLN3/IJmrMG+25a4DT
    ///    +nZImJjnTNHJUtxAA+o0KPKfHEcAFs9a3CL5Oebe/ydHJUwYFd
    ///    WwuQ1MWiy6IesKvjL5rL9WjXUb9MwT9bpObYLGOKi1Qh
    /// S: + or//EoAADZI=
    /// C: DiAF5A4gA+oOIALuBkAAmw==
    /// S: +OK Kerberos V4 authentication successful
    AUTH,
    /// CAPA returns a list of capabilities supported by the POP3 server
    ///
    /// # Restrictions
    ///
    /// Available in both the AUTHORIZATION and TRANSACTION states
    ///
    /// # Discussion
    ///
    /// An -ERR response indicates the capability command is not
    /// implemented and the client will have to probe for
    /// capabilities as before.
    ///
    /// An +OK response is followed by a list of capabilities, one
    /// per line.  Each capability name MAY be followed by a single
    /// space and a space-separated list of parameters.  Each
    /// capability line is limited to 512 octets (including the
    /// CRLF).  The capability list is terminated by a line
    /// containing a termination octet (".") and a CRLF pair.
    ///
    /// ## Available capabilities
    ///
    /// - TOP
    /// - USER
    /// - SASL
    /// - RESP-CODES
    /// - LOGIN-DELAY
    /// - PIPELINING
    /// - EXPIRE
    /// - UIDL
    /// - IMPLEMENTATION
    ///
    /// # Syntax
    ///
    /// C: CAPA
    /// S: +OK <msg>
    /// S: <capability>
    /// S: .
    ///
    /// # Examples
    ///
    /// C: CAPA
    /// S: +OK Capability list follows
    /// S: TOP
    /// S: USER
    /// S: SASL CRAM-MD5 KERBEROS_V4
    /// S: RESP-CODES
    /// S: LOGIN-DELAY 900
    /// S: PIPELINING
    /// S: EXPIRE 60
    /// S: UIDL
    /// S: IMPLEMENTATION Shlemazle-Plotz-v302
    /// S: .
    CAPA,
    /// DELE will delete a mail from maildrop
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// The POP3 server marks the message as deleted.  Any future
    /// reference to the message-number associated with the message
    /// in a POP3 command generates an error.  The POP3 server does
    /// not actually delete the message until the POP3 session
    /// enters the UPDATE state.
    ///
    /// # Syntax
    ///
    /// C: DELE <id>
    /// S: +OK [msg]
    ///
    /// # Examples
    ///
    /// C: DELE 1
    /// S: +OK message 1 deleted
    ///
    /// C: DELE 2
    /// S: -ERR message 2 already deleted
    DELE,
    /// LIST will list maildrop mails
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// If an argument was given and the POP3 server issues a
    /// positive response with a line containing information for
    /// that message.  This line is called a "scan listing" for
    /// that message.
    ///
    /// If no argument was given and the POP3 server issues a
    /// positive response, then the response given is multi-line.
    /// After the initial +OK, for each message in the maildrop,
    /// the POP3 server responds with a line containing
    /// information for that message.  This line is also called a
    /// "scan listing" for that message.  If there are no
    /// messages in the maildrop, then the POP3 server responds
    /// with no scan listings--it issues a positive response
    /// followed by a line containing a termination octet and a
    /// CRLF pair.
    ///
    /// In order to simplify parsing, all POP3 servers are
    /// required to use a certain format for scan listings.  A
    /// scan listing consists of the message-number of the
    /// message, followed by a single space and the exact size of
    /// the message in octets.  Methods for calculating the exact
    /// size of the message are described in the "Message Format"
    /// section below.  This memo makes no requirement on what
    /// follows the message size in the scan listing.  Minimal
    /// implementations should just end that line of the response
    /// with a CRLF pair.  More advanced implementations may
    /// include other information, as parsed from the message.
    ///
    ///    NOTE: This memo STRONGLY discourages implementations
    ///    from supplying additional information in the scan
    ///    listing.  Other, optional, facilities are discussed
    ///    later on which permit the client to parse the messages
    ///    in the maildrop.
    ///
    /// Note that messages marked as deleted are not listed.
    ///
    /// # Syntax
    ///
    /// ## List all mails
    ///
    /// C: LIST
    /// S: +OK [msg]
    /// S: <id> <size>
    /// S: .
    ///
    /// ## List single mail
    ///
    /// C: LIST <id>
    /// S: +OK <id> <size>
    ///
    /// # Examples
    ///
    /// C: LIST
    /// S: +OK 2 messages (320 octets)
    /// S: 1 120
    /// S: 2 200
    /// S: .
    ///
    /// C: LIST 2
    /// S: +OK 2 200
    ///
    /// C: LIST 3
    /// S: -ERR no such message, only 2 messages in maildrop
    LIST,
    /// NOOP will do nothing, used to keep heartbeat.
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// The POP3 server does nothing, it merely replies with a positive response.
    ///
    /// # Syntax
    ///
    /// C: NOOP
    /// S: +OK
    ///
    /// # Examples
    ///
    /// C: NOOP
    /// S: +OK
    NOOP,
    /// QUIT will terminate this connection by client.
    ///
    /// # Syntax
    ///
    /// C: QUIT
    /// S: +OK [msg]
    ///
    /// # Examples
    ///
    /// C: QUIT
    /// S: +OK dewey POP3 server signing off (maildrop empty)
    QUIT,
    /// PASS is used to send password.
    ///
    /// # Restrictions
    ///
    /// Only be given in the AUTHORIZATION state immediately after a successful USER command
    ///
    /// # Discussion
    ///
    /// When the client issues the PASS command, the POP3 server
    /// uses the argument pair from the USER and PASS commands to
    /// determine if the client should be given access to the
    /// appropriate maildrop.
    ///
    /// Since the PASS command has exactly one argument, a POP3
    /// server may treat spaces in the argument as part of the
    /// password, instead of as argument separators.
    ///
    /// # Syntax
    ///
    /// C: PASS <passowrd>
    /// S: +OK [msg]
    ///
    /// # Examples
    ///
    /// C: USER mrose
    /// S: +OK mrose is a real hoopy frood
    /// C: PASS secret
    /// S: -ERR maildrop already locked
    ///
    /// C: USER mrose
    /// S: +OK mrose is a real hoopy frood
    /// C: PASS secret
    /// S: +OK mrose's maildrop has 2 messages (320 octets)
    PASS,
    /// RETR will be used to retrieve a mail
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// If the POP3 server issues a positive response, then the
    /// response given is multi-line.  After the initial +OK, the
    /// POP3 server sends the message corresponding to the given
    /// message-number, being careful to byte-stuff the termination
    /// character (as with all multi-line responses).
    ///
    /// # Syntax
    ///
    /// C: RETR <id>
    /// S: +OK [msg]
    /// S: <the POP3 server sends the entire message here>
    /// S: .
    ///
    /// # Examples
    ///
    /// C: RETR 1
    /// S: +OK 120 octets
    /// S: <the POP3 server sends the entire message here>
    /// S: .
    RETR,
    /// RSET will reset the connection to initial state.
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// If any messages have been marked as deleted by the POP3
    /// server, they are unmarked.  The POP3 server then replies
    /// with a positive response.
    ///
    /// # Syntax
    ///
    /// C: RSET
    /// S: +OK [msg]
    ///
    /// # Examples
    ///
    /// C: RSET
    /// S: +OK maildrop has 2 messages (320 octets)
    RSET,
    /// STAT will show the stat of maildrop.
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// The POP3 server issues a positive response with a line
    /// containing information for the maildrop.  This line is
    /// called a "drop listing" for that maildrop.
    ///
    /// In order to simplify parsing, all POP3 servers are
    /// required to use a certain format for drop listings.  The
    /// positive response consists of "+OK" followed by a single
    /// space, the number of messages in the maildrop, a single
    /// space, and the size of the maildrop in octets.  This memo
    /// makes no requirement on what follows the maildrop size.
    /// Minimal implementations should just end that line of the
    /// response with a CRLF pair.  More advanced implementations
    /// may include other information.
    ///
    ///     NOTE: This memo STRONGLY discourages implementations
    ///     from supplying additional information in the drop
    ///     listing.  Other, optional, facilities are discussed
    ///     later on which permit the client to parse the messages
    ///     in the maildrop.
    ///
    /// Note that messages marked as deleted are not counted in
    /// either total.
    ///
    /// # Syntax
    ///
    /// C: STAT
    /// S: OK <count> <size>
    ///
    /// # Examples
    ///
    /// C: STAT
    /// S: +OK 2 320
    STAT,
    /// TOP will used to send top lines of messages.
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    ///
    /// If the POP3 server issues a positive response, then the
    /// response given is multi-line.  After the initial +OK, the
    /// POP3 server sends the headers of the message, the blank
    /// line separating the headers from the body, and then the
    /// number of lines of the indicated message's body, being
    /// careful to byte-stuff the termination character (as with
    /// all multi-line responses).
    ///
    /// Note that if the number of lines requested by the POP3
    /// client is greater than than the number of lines in the
    /// body, then the POP3 server sends the entire message
    ///
    /// # Syntax
    ///
    /// C: TOP <id> <lines>
    /// S: +OK
    /// S: <the POP3 server sends the headers of the
    ///    message, a blank line, and the first <lines>
    ///    of the body of the message>
    /// S: .
    ///
    /// # Examples
    ///
    /// C: TOP 1 10
    /// S: +OK
    /// S: <the POP3 server sends the headers of the
    ///    message, a blank line, and the first 10 lines
    ///    of the body of the message>
    /// S: .
    ///
    /// C: TOP 100 3
    /// S: -ERR no such message
    TOP,
    /// UIDL will used to do "unique-id listing".
    ///
    /// # Restrictions
    ///
    /// Only be given in the TRANSACTION state
    ///
    /// # Discussion
    /// If an argument was given and the POP3 server issues a positive
    /// response with a line containing information for that message.
    /// This line is called a "unique-id listing" for that message.
    ///
    /// If no argument was given and the POP3 server issues a positive
    /// response, then the response given is multi-line.  After the
    /// initial +OK, for each message in the maildrop, the POP3 server
    /// responds with a line containing information for that message.
    /// This line is called a "unique-id listing" for that message.
    ///
    /// In order to simplify parsing, all POP3 servers are required to
    /// use a certain format for unique-id listings.  A unique-id
    /// listing consists of the message-number of the message,
    /// followed by a single space and the unique-id of the message.
    /// No information follows the unique-id in the unique-id listing.
    ///
    /// The unique-id of a message is an arbitrary server-determined
    /// string, consisting of one to 70 characters in the range 0x21
    /// to 0x7E, which uniquely identifies a message within a
    /// maildrop and which persists across sessions.  This
    /// persistence is required even if a session ends without
    /// entering the UPDATE state.  The server should never reuse an
    /// unique-id in a given maildrop, for as long as the entity
    /// using the unique-id exists.
    ///
    /// Note that messages marked as deleted are not listed.
    ///
    /// While it is generally preferable for server implementations
    /// to store arbitrarily assigned unique-ids in the maildrop,
    /// this specification is intended to permit unique-ids to be
    /// calculated as a hash of the message.  Clients should be able
    /// to handle a situation where two identical copies of a
    /// message in a maildrop have the same unique-id.
    ///
    /// # Syntax
    ///
    /// ## List all mails with unique id
    ///
    /// C: UIDL
    /// S: +OK
    /// S: <id> <unique-id>
    /// S: .
    ///
    /// ## List single mail with unique id
    ///
    /// C: UIDL <id>
    /// S: +OK <id> <unique-id>
    ///
    /// # Examples
    ///
    /// C: UIDL
    /// S: +OK
    /// S: 1 whqtswO00WBw418f9t5JxYwZ
    /// S: 2 QhdPYR:00WBw1Ph7x7
    /// S: .
    ///
    /// C: UIDL 2
    /// S: +OK 2 QhdPYR:00WBw1Ph7x7
    ///
    /// C: UIDL 3
    /// S: -ERR no such message, only 2 messages in maildrop
    UIDL,
    /// USER is used to send user name
    ///
    /// # Restrictions
    ///
    /// Only be given in the AUTHORIZATION state after the POP3 greeting or
    /// after an unsuccessful USER or PASS command
    ///
    /// # Discussion
    ///
    /// To authenticate using the USER and PASS command
    /// combination, the client must first issue the USER
    /// command.  If the POP3 server responds with a positive
    /// status indicator ("+OK"), then the client may issue
    /// either the PASS command to complete the authentication,
    /// or the QUIT command to terminate the POP3 session.  If
    /// the POP3 server responds with a negative status indicator
    /// ("-ERR") to the USER command, then the client may either
    /// issue a new authentication command or may issue the QUIT
    /// command.
    ///
    /// The server may return a positive response even though no
    /// such mailbox exists.  The server may return a negative
    /// response if mailbox exists, but does not permit plaintext
    /// password authentication.
    ///
    /// # Syntax
    ///
    /// C: USER <username>
    /// S: +OK [msg]
    ///
    /// # Examples
    ///
    /// C: USER frated
    /// S: -ERR sorry, no mailbox for frated here
    ///
    /// C: USER mrose
    /// S: +OK mrose is a real hoopy frood
    USER,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "USER" => Command::USER,
            "PASS" => Command::PASS,
            "STAT" => Command::STAT,
            "UIDL" => Command::UIDL,
            "LIST" => Command::LIST,
            "RETR" => Command::RETR,
            "DELE" => Command::DELE,
            "NOOP" => Command::NOOP,
            "RSET" => Command::RSET,
            "QUIT" => Command::QUIT,
            "APOP" => Command::APOP,
            "TOP" => Command::TOP,
            "AUTH" => Command::AUTH,
            "CAPA" => Command::CAPA,
            _ => return Err(anyhow::anyhow!("invalid command: {}", s)),
        })
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let v = match self {
            Command::USER => "USER",
            Command::PASS => "PASS",
            Command::STAT => "STAT",
            Command::UIDL => "UIDL",
            Command::LIST => "LIST",
            Command::RETR => "RETR",
            Command::DELE => "DELE",
            Command::NOOP => "NOOP",
            Command::RSET => "RSET",
            Command::QUIT => "QUIT",
            Command::APOP => "APOP",
            Command::TOP => "TOP",
            Command::AUTH => "AUTH",
            Command::CAPA => "CAPA",
        };

        write!(f, "{}", v)
    }
}

impl From<&Request> for Command {
    fn from(v: &Request) -> Self {
        match v {
            Request::APOP { .. } => Command::APOP,
            Request::AUTH(_) => Command::AUTH,
            Request::CAPA => Command::CAPA,
            Request::DELE(_) => Command::DELE,
            Request::LIST(_) => Command::LIST,
            Request::NOOP => Command::NOOP,
            Request::PASS(_) => Command::PASS,
            Request::QUIT => Command::QUIT,
            Request::RETR(_) => Command::RETR,
            Request::RSET => Command::RSET,
            Request::STAT => Command::STAT,
            Request::TOP { .. } => Command::TOP,
            Request::UIDL(_) => Command::UIDL,
            Request::USER(_) => Command::USER,
            _ => panic!("invalid command for request: {:?}", v),
        }
    }
}

impl From<&Response> for Command {
    fn from(v: &Response) -> Self {
        match v {
            Response::AUTH(_) => Command::AUTH,
            Response::CAPA(_) => Command::CAPA,
            Response::DELE => Command::DELE,
            Response::LIST(_) => Command::LIST,
            Response::NOOP => Command::NOOP,
            Response::PASS(_) => Command::PASS,
            Response::QUIT => Command::QUIT,
            Response::RETR(_) => Command::RETR,
            Response::STAT { .. } => Command::STAT,
            Response::RSET => Command::RSET,
            Response::USER(_) => Command::USER,
            // GREET and ERR doesn't have related commend.
            _ => panic!("invalid command for response: {:?}", v),
        }
    }
}

#[derive(Debug)]
pub enum Request {
    APOP { username: String, digest: String },
    AUTH(Option<String>),
    CAPA,
    DELE(usize),
    LIST(Option<usize>),
    NOOP,
    PASS(String),
    QUIT,
    RETR(usize),
    RSET,
    STAT,
    TOP { id: usize, lines: usize },
    UIDL(Option<usize>),
    USER(String),
}

impl Request {
    pub fn from_str(v: &str) -> Result<Request> {
        let v = v.strip_suffix("\r\n").unwrap();

        let vs: Vec<&str> = v.split(" ").filter(|s| !s.is_empty()).collect();
        let cmd = Command::from_str(vs[0])?;

        let req = match cmd {
            Command::USER => {
                if vs.len() != 2 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::USER(vs[1].to_string())
            }
            Command::PASS => {
                if vs.len() != 2 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::PASS(vs[1].to_string())
            }
            Command::STAT => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::STAT
            }
            Command::UIDL => match vs.len() {
                1 => Request::UIDL(None),
                2 => {
                    let msg = usize::from_str(vs[1])?;

                    Request::UIDL(Some(msg))
                }
                _ => {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }
            },
            Command::LIST => match vs.len() {
                1 => Request::LIST(None),
                2 => {
                    let msg = usize::from_str(vs[1])?;

                    Request::LIST(Some(msg))
                }
                _ => {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }
            },
            Command::RETR => {
                if vs.len() != 2 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                let msg = usize::from_str(vs[1])?;

                Request::RETR(msg)
            }
            Command::DELE => {
                if vs.len() != 2 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                let msg = usize::from_str(vs[1])?;

                Request::DELE(msg)
            }
            Command::NOOP => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::NOOP
            }
            Command::RSET => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::RSET
            }
            Command::QUIT => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::QUIT
            }
            Command::TOP => {
                if vs.len() != 3 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                let id = usize::from_str(vs[1])?;
                let lines = usize::from_str(vs[2])?;

                Request::TOP { id, lines }
            }
            Command::APOP => {
                if vs.len() != 3 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::APOP {
                    username: vs[1].to_string(),
                    digest: vs[2].to_string(),
                }
            }
            Command::AUTH => match vs.len() {
                1 => Request::AUTH(None),
                2 => Request::AUTH(Some(vs[1].to_string())),
                _ => {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }
            },
            Command::CAPA => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid request for {}: {}", cmd, v));
                }

                Request::CAPA
            }
        };

        Ok(req)
    }

    pub fn to_string(&self) -> Result<String> {
        let mut f = String::new();

        match self {
            Request::CAPA | Request::NOOP | Request::QUIT | Request::RSET | Request::STAT => {
                write!(&mut f, "{}\r\n", Command::from(self))?
            }
            Request::DELE(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            Request::PASS(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            Request::RETR(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            Request::USER(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            Request::AUTH(v) => match v {
                None => write!(&mut f, "{}\r\n", Command::from(self))?,
                Some(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            },
            Request::LIST(v) => match v {
                None => write!(&mut f, "{}\r\n", Command::from(self))?,
                Some(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            },
            Request::UIDL(v) => match v {
                None => write!(&mut f, "{}\r\n", Command::from(self))?,
                Some(v) => write!(&mut f, "{} {}\r\n", Command::from(self), v)?,
            },
            Request::APOP { username, digest } => write!(
                &mut f,
                "{} {} {}\r\n",
                Command::from(self),
                username,
                digest
            )?,
            Request::TOP { id, lines } => {
                write!(&mut f, "{} {} {}\r\n", Command::from(self), id, lines)?
            }
        }

        Ok(f)
    }
}

#[derive(Debug)]
pub enum Response {
    AUTH(AuthResponse),
    CAPA(Vec<String>),
    DELE,
    GREET(String),
    LIST(ListResponse),
    NOOP,
    PASS(String),
    QUIT,
    RETR(String),
    STAT { count: usize, size: usize },
    RSET,
    USER(String),

    ERR(String),
}

#[derive(Debug)]
pub enum ListResponse {
    Single(MessageMeta),
    All {
        count: usize,
        messages: Vec<MessageMeta>,
    },
}

#[derive(Debug)]
pub enum AuthResponse {
    All(Vec<String>),
}

impl Response {
    pub fn to_string(&self) -> Result<String> {
        let mut f = String::new();

        match self {
            Response::AUTH(v) => match v {
                AuthResponse::All(v) => {
                    write!(&mut f, "+OK {} auth methods\r\n", v.len())?;
                    for v in v.iter() {
                        write!(&mut f, "{}\r\n", v)?;
                    }
                    write!(&mut f, ".\r\n")?
                }
            },
            Response::CAPA(v) => {
                write!(&mut f, "+OK Capability list follows\r\n")?;
                for v in v.iter() {
                    write!(&mut f, "{}\r\n", v)?;
                }
                write!(&mut f, ".\r\n")?
            }
            Response::DELE => write!(&mut f, "+OK\r\n")?,
            Response::GREET(v) => write!(&mut f, "+OK {}\r\n", v)?,
            Response::LIST(v) => match v {
                ListResponse::All { count, messages } => {
                    write!(&mut f, "+OK {} messages\r\n", count)?;
                    for v in messages.iter() {
                        write!(&mut f, "{} {}\r\n", v.id, v.size)?;
                    }
                    write!(&mut f, ".\r\n")?
                }
                ListResponse::Single(v) => write!(&mut f, "+OK {} {}\r\n", v.id, v.size)?,
            },
            Response::NOOP => write!(&mut f, "+OK\r\n")?,
            Response::PASS(v) => write!(&mut f, "+OK {}\r\n", v)?,
            Response::QUIT => write!(&mut f, "+OK\r\n")?,
            Response::RETR(v) => {
                write!(&mut f, "+OK\r\n")?;
                write!(&mut f, "{}", v)?;
                write!(&mut f, ".\r\n")?
            }
            Response::STAT { count, size } => write!(&mut f, "+OK {} {}\r\n", count, size)?,
            Response::RSET => write!(&mut f, "+OK\r\n")?,
            Response::USER(v) => write!(&mut f, "+OK {}\r\n", v)?,

            Response::ERR(v) => write!(&mut f, "-ERR {}\r\n", v)?,
        }

        Ok(f)
    }

    pub fn from_str(v: &str, cmd: Command) -> anyhow::Result<Response> {
        if !v.starts_with("-ERR") || !v.starts_with("+OK") {
            return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
        }

        if v.starts_with("-ERR") {
            let v = v.strip_prefix("-ERR ").unwrap();
            let v = v.strip_suffix("\r\n").unwrap();

            return Ok(Response::ERR(v.to_string()));
        }

        let vs: Vec<&str> = v.split("\r\n").filter(|s| !s.is_empty()).collect();

        let resp = match cmd {
            Command::USER => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::USER(vs[0].strip_prefix("+OK ").unwrap().to_string())
            }
            Command::PASS => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::PASS(vs[0].strip_prefix("+OK ").unwrap().to_string())
            }
            Command::STAT => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                let vs: Vec<&str> = vs[0].split(" ").collect();

                if vs.len() != 3 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::STAT {
                    count: usize::from_str(vs[1])?,
                    size: usize::from_str(vs[2])?,
                }
            }
            Command::UIDL => unimplemented!(),
            Command::LIST => unimplemented!(),
            Command::RETR => unimplemented!(),
            Command::DELE => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::DELE
            }
            Command::NOOP => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::NOOP
            }
            Command::RSET => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::RETR(vs[0].strip_prefix("+OK ").unwrap().to_string())
            }
            Command::QUIT => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                Response::QUIT
            }
            Command::TOP => unimplemented!(),
            Command::APOP => unimplemented!(),
            Command::AUTH => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                unimplemented!()
            }
            Command::CAPA => {
                if vs.len() != 1 {
                    return Err(anyhow::anyhow!("invalid response for {}: {}", cmd, v));
                }

                unimplemented!()
            }
        };

        Ok(resp)
    }
}

enum State {
    AUTHORIZATION,
    TRANSACTION,
    /// When the client issues the QUIT command from the TRANSACTION state,
    /// the POP3 session enters the UPDATE state.  (Note that if the client
    /// issues the QUIT command from the AUTHORIZATION state, the POP3
    /// session terminates but does NOT enter the UPDATE state.)
    ///
    /// If a session terminates for some reason other than a client-issued
    /// QUIT command, the POP3 session does NOT enter the UPDATE state and
    /// MUST not remove any messages from the maildrop.
    UPDATE,
}

#[derive(Debug, Copy, Clone)]
pub struct MessageMeta {
    pub id: usize,
    pub size: usize,
}
