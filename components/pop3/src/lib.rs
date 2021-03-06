/// # Example POP3 Session
///
/// S: <wait for connection on TCP port 110>
/// C: <open connection>
/// S:    +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
/// C:    APOP mrose c4c9334bac560ecc979e58001b3e22fb
/// S:    +OK mrose's maildrop has 2 messages (320 octets)
/// C:    STAT
/// S:    +OK 2 320
/// C:    LIST
/// S:    +OK 2 messages (320 octets)
/// S:    1 120
/// S:    2 200
/// S:    .
/// C:    RETR 1
/// S:    +OK 120 octets
/// S:    <the POP3 server sends message 1>
/// S:    .
/// C:    DELE 1
/// S:    +OK message 1 deleted
/// C:    RETR 2
/// S:    +OK 200 octets
/// S:    <the POP3 server sends message 2>
/// S:    .
/// C:    DELE 2
/// S:    +OK message 2 deleted
/// C:    QUIT
/// S:    +OK dewey POP3 server signing off (maildrop empty)
/// C:  <close connection>
/// S:  <wait for next connection>
pub use proto::*;

mod proto;
