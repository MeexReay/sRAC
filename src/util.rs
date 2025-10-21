use std::{error::Error, io::Read};

use colored::{Color, Colorize};
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
  pub static ref DATE_REGEX: Regex = Regex::new(r"\[(.*?)\] (.*)").unwrap();
  pub static ref IP_REGEX: Regex = Regex::new(r"\{(.*?)\} (.*)").unwrap();
  pub static ref COLORED_USERNAMES: Vec<(Regex, Color)> = vec![
      (Regex::new(r"\u{B9AC}\u{3E70}<(.*?)> (.*)").unwrap(), Color::Green),             // bRAC
      (Regex::new(r"\u{2550}\u{2550}\u{2550}<(.*?)> (.*)").unwrap(), Color::BrightRed), // CRAB
      (Regex::new(r"\u{00B0}\u{0298}<(.*?)> (.*)").unwrap(), Color::Magenta),           // Mefidroniy
      (Regex::new(r"<(.*?)> (.*)").unwrap(), Color::Cyan),                              // clRAC
  ];
  pub static ref ANSI_REGEX: Regex = Regex::new(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])").unwrap();
  pub static ref CONTROL_CHARS_REGEX: Regex = Regex::new(r"[\x00-\x1F\x7F]").unwrap();
  pub static ref AVATAR_REGEX: Regex = Regex::new(r"(.*)\x06!!AR!!(.*)").unwrap();
}

pub fn sanitize_text(input: &str) -> String {
    let without_ansi = ANSI_REGEX.replace_all(input, "");
    let cleaned_text = CONTROL_CHARS_REGEX.replace_all(&without_ansi, "");
    cleaned_text.into_owned()
}

pub fn format_message(enable_ip_viewing: bool, message: String) -> Option<String> {
    let message = sanitize_text(&message);

    let date = DATE_REGEX.captures(&message)?;
    let (date, message) = (
        date.get(1)?.as_str().to_string(),
        date.get(2)?.as_str().to_string(),
    );

    let (ip, message) = if let Some(message) = IP_REGEX.captures(&message) {
        (
            Some(message.get(1)?.as_str().to_string()),
            message.get(2)?.as_str().to_string(),
        )
    } else {
        (None, message)
    };

    let message = message
        .trim_start_matches("(UNREGISTERED)")
        .trim_start_matches("(UNAUTHORIZED)")
        .trim_start_matches("(UNAUTHENTICATED)")
        .trim()
        .to_string()
        + " ";

    let prefix = if enable_ip_viewing {
        if let Some(ip) = ip {
            format!(
                "{}{} [{}]",
                ip,
                " ".repeat(if 15 >= ip.chars().count() {
                    15 - ip.chars().count()
                } else {
                    0
                }),
                date
            )
        } else {
            format!("{} [{}]", " ".repeat(15), date)
        }
    } else {
        format!("[{}]", date)
    };

    Some(if let Some(captures) = find_username_color(&message) {
        let nick = captures.0;
        let content = captures.1;
        let color = captures.2;

        format!(
            "{} {} {}",
            prefix.white().dimmed(),
            format!("<{}>", nick).color(color).bold(),
            content.white().blink()
        )
    } else {
        format!("{} {}", prefix.white().dimmed(), message.white().blink())
    })
}

pub fn find_username_color(message: &str) -> Option<(String, String, Color)> {
    for (re, color) in COLORED_USERNAMES.iter() {
        if let Some(captures) = re.captures(message) {
            return Some((
                captures[1].to_string(),
                captures[2].to_string(),
                color.clone(),
            ));
        }
    }
    None
}

pub fn read_u32<R>(cursor: &mut R) -> Result<u32, Box<dyn Error>>
where
    R: Read,
{
    let mut buf = [0; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub fn read_string<R>(cursor: &mut R, len: usize) -> Result<String, Box<dyn Error>>
where
    R: Read,
{
    let mut buf = vec![0; len];
    cursor.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| e.into())
}

pub fn grab_avatar(message: &str) -> (String, Option<String>) {
    if let Some(message) = AVATAR_REGEX.captures(&message) {
        (
            message.get(1).unwrap().as_str().to_string(),
            Some(message.get(2).unwrap().as_str().to_string()),
        )
    } else {
        (message.to_string(), None)
    }
}

// TODO: rewrite this bezobrazie
pub fn parse_rac_url(url: &str) -> Option<(String, bool, bool)> {
    let (scheme, url) = url.split_once("://").unwrap_or(("rac", url));
    let (host, _) = url.split_once("/").unwrap_or((url, ""));
    match scheme.to_lowercase().as_str() {
        "rac" => Some((
            if host.contains(":") {
                host.to_string()
            } else {
                format!("{host}:42666")
            },
            false,
            false,
        )),
        "racs" => Some((
            if host.contains(":") {
                host.to_string()
            } else {
                format!("{host}:42667")
            },
            true,
            false,
        )),
        "wrac" => Some((
            if host.contains(":") {
                host.to_string()
            } else {
                format!("{host}:52666")
            },
            false,
            true,
        )),
        "wracs" => Some((
            if host.contains(":") {
                host.to_string()
            } else {
                format!("{host}:52667")
            },
            true,
            true,
        )),
        _ => None,
    }
}
