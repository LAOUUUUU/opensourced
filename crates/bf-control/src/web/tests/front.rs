//! The front page's content: its sections and the menu that names them, the specification
//! sheet and the numbers its privacy section draws, the pictures and the words beside them,
//! and the headline (`research/redesign/RESEARCH.md`, then the editorial direction of
//! `research/redesign-editorial/RESEARCH.md` and decision 028).

use super::legal::{part, text};
use super::*;

/// The text between `<{tag} ...>` of each `<section` in `html`: its id, or its class when it
/// has none (the first and last sections have no id).
fn section_names(html: &str) -> Vec<String> {
    html.split("<section")
        .skip(1)
        .map(|rest| {
            let tag = rest.split('>').next().unwrap();
            for attribute in ["id=\"", "class=\""] {
                if let Some(value) = tag.split(attribute).nth(1) {
                    return value.split('"').next().unwrap().to_string();
                }
            }
            panic!("a section with neither id nor class: {tag}");
        })
        .collect()
}

#[test]
fn the_front_page_has_its_nine_sections_in_this_order() {
    // The editorial order: the first screen, one statement set huge, how it works, the map of
    // the servers, the specification sheet (still `features`, so old links land on it), then
    // what we keep, funding, questions and the last word.
    assert_eq!(
        section_names(INDEX),
        [
            "hero", "why", "how", "nodes", "features", "privacy", "funding", "faq", "closing"
        ],
        "hero, why, how it works, servers, specification, privacy, funding, questions, closing"
    );
    // The ids the menu and footer link to are the ones the tests and the stylesheet name.
    for id in [
        "why", "features", "how", "nodes", "privacy", "funding", "faq",
    ] {
        assert_eq!(
            INDEX.matches(&format!("<section id=\"{id}\">")).count(),
            1,
            "{id}: a bare opening tag, because other tests split on it"
        );
    }
}

#[test]
fn the_menu_names_the_sections_in_the_order_the_page_has_them() {
    let header = part(INDEX, "<header class=\"top\">", "</header>");
    let in_menu: Vec<usize> = ["why", "how", "nodes", "privacy", "faq"]
        .iter()
        .map(|id| {
            header
                .find(&format!("href=\"/#{id}\""))
                .unwrap_or_else(|| panic!("no menu entry for {id}"))
        })
        .collect();
    assert!(in_menu.windows(2).all(|w| w[0] < w[1]), "menu order");
    let on_page: Vec<usize> = ["why", "how", "nodes", "privacy", "faq"]
        .iter()
        .map(|id| INDEX.find(&format!("<section id=\"{id}\">")).unwrap())
        .collect();
    assert!(on_page.windows(2).all(|w| w[0] < w[1]), "page order");
}

#[test]
fn the_retention_rows_and_bars_use_the_numbers_the_code_uses() {
    use crate::signin::{
        CODE_LIFETIME_SECS, KEEP_SECS, KEPT_SESSION_MAX_SECS, SESSION_LIFETIME_SECS,
    };
    let day = 86_400;
    let backup_keep: u64 = include_str!("../../../../../deploy/bf-backup-receive")
        .split("BF_BACKUP_KEEP:-")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .unwrap()
        .parse()
        .unwrap();
    // Each row: the number written on it, and the seconds the code holds that long.
    let rows = [
        (
            format!("{} minutes", bf_common::wg::FORGET_IDLE_AFTER_SECS / 60),
            bf_common::wg::FORGET_IDLE_AFTER_SECS,
        ),
        (
            format!("{} minutes", CODE_LIFETIME_SECS / 60),
            CODE_LIFETIME_SECS,
        ),
        (format!("{} day", KEEP_SECS / day), KEEP_SECS),
        (format!("{backup_keep} days"), backup_keep * day),
        (
            format!("{} days", SESSION_LIFETIME_SECS / day),
            SESSION_LIFETIME_SECS,
        ),
        (
            format!("{} days", KEPT_SESSION_MAX_SECS / day),
            KEPT_SESSION_MAX_SECS,
        ),
    ];
    let list = part(INDEX, "<ol class=\"retention\">", "</ol>");
    let items: Vec<&str> = list.split("<li>").skip(1).collect();
    assert_eq!(items.len(), rows.len(), "one row for each number");
    // The longest row is the widest bar; every other bar is log10 of its minutes over log10 of
    // the longest's, so one minute would be no bar at all.
    let longest = (rows[5].1 as f64 / 60.0).log10();
    for (n, ((label, seconds), item)) in rows.iter().zip(&items).enumerate() {
        let said = item
            .split("<strong>")
            .nth(1)
            .and_then(|rest| rest.split("</strong>").next())
            .unwrap();
        assert_eq!(said, label, "row {} says its number", n + 1);
        let class = format!("class=\"bar b{}\"", n + 1);
        assert!(item.contains(&class), "row {} draws {class}", n + 1);
        let want = (*seconds as f64 / 60.0).log10() / longest * 100.0;
        let rule = SITE_CSS
            .split(&format!(".b{} {{ width: ", n + 1))
            .nth(1)
            .and_then(|rest| rest.split('%').next())
            .unwrap_or_else(|| panic!("no width for .b{}", n + 1))
            .parse::<f64>()
            .unwrap();
        assert!(
            (rule - want).abs() < 1.5,
            "bar {} is {rule}% wide; {seconds} s is {want:.1}% of the longest on a log scale of minutes",
            n + 1
        );
    }
    assert!(
        items[3].contains(&format!("newest {backup_keep} nightly copies")),
        "{}",
        items[3]
    );
    assert!(
        text(list).contains("counted from your last visit if you ticked"),
        "the 60 days is the renewing session"
    );
}

#[test]
fn every_line_the_front_page_says_is_never_kept_is_said_by_the_privacy_policy() {
    let never = part(INDEX, "<ul class=\"plain never\">", "</ul>");
    let policy = text(PRIVACY);
    let lines: Vec<String> = never
        .split("<li>")
        .skip(1)
        .map(|item| text(item.split("</li>").next().unwrap()))
        .collect();
    assert_eq!(lines.len(), 5, "five things, as in the policy's section 4");
    for line in lines {
        assert!(
            policy.contains(&line),
            "the privacy policy does not say {line:?}"
        );
    }
    // The section that holds them still opens with the heading other tests split on.
    assert!(INDEX.contains("<h2>What we keep</h2>"));
}

#[test]
fn every_picture_is_decoration_and_the_words_beside_it_say_what_it_shows() {
    for picture in INDEX.split("<svg").skip(1) {
        let tag = picture.split('>').next().unwrap();
        assert!(tag.contains("aria-hidden=\"true\""), "{tag}");
        assert!(tag.contains("focusable=\"false\""), "{tag}");
    }
    // The first screen's picture is the mark itself, enlarged; it says nothing the headline
    // beside it does not, so it carries no words.
    let hero = part(INDEX, "<section class=\"hero\">", "</section>");
    assert_eq!(hero.matches("<svg").count(), 1, "one picture: {hero}");
    assert!(hero.contains("<svg class=\"hero-art\""), "{hero}");
    // The switch's figure explains: three captions in order, a line that says it is an
    // illustration, and both verdicts written out, which match what `/check` says.
    let compare = part(INDEX, "<figure class=\"compare\">", "</figure>");
    let mut last = 0;
    for who in ["Your device", "Barely-free server", "The sites you visit"] {
        let at = compare
            .find(&format!("<strong>{who}</strong>"))
            .unwrap_or_else(|| panic!("caption {who}"));
        assert!(at > last, "captions in order");
        last = at;
    }
    assert!(compare.contains("<figcaption>"), "{compare}");
    let words = text(compare);
    assert!(words.contains("It is not live data."), "{words}");
    assert!(
        words.contains("Your network can see which sites you connect to"),
        "{words}"
    );
    assert!(
        words.contains("The sites see the server's address, not yours."),
        "{words}"
    );
}

#[test]
fn nothing_on_the_page_moves_forever_so_there_is_no_pause_control() {
    // Hairline had a pulse and beating rings, and a "Pause motion" box for them (WCAG 2.2.2).
    // The editorial page moves once and settles, so the box went with them.
    assert!(!INDEX.contains("id=\"calm\""), "no pause control");
    assert!(!SITE_CSS.contains(".calm"), "and no rule for one");
    // The checkbox was never a form field: the theme buttons stay the page's only form.
    assert_eq!(forms(INDEX), vec![THEME_FORM_TAG]);
}

#[test]
fn the_specification_names_every_feature_with_the_numbers_the_code_uses() {
    let sheet = part(INDEX, "<section id=\"features\">", "</section>");
    // A description list: a term and its value on each row.
    let terms = sheet.matches("<dt>").count();
    assert_eq!(terms, sheet.matches("<dd>").count(), "{sheet}");
    assert!(terms >= 10, "{terms} rows");
    let words = text(sheet);
    // Every feature the old cards named is still here, in its own words.
    for said in [
        "WireGuard",
        "inside each server's kernel",
        "AmneziaWG",
        "light restrictions",
        "Known trackers are blocked by default",
        "It does not block ads.",
        "malware",
        "Quad9",
        "closest server",
        "ClashMi",
        "made by KaringX",
        "six-digit code",
        "made once, shown once",
        "never stored",
        "every night",
        "MIT",
        "donations",
    ] {
        assert!(words.contains(said), "the sheet says {said:?}: {words}");
    }
    let backup_keep: u64 = include_str!("../../../../../deploy/bf-backup-receive")
        .split("BF_BACKUP_KEEP:-")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .unwrap()
        .parse()
        .unwrap();
    for number in [
        format!("{} minutes", crate::signin::CODE_LIFETIME_SECS / 60),
        format!(
            "about {} minutes",
            bf_common::wg::FORGET_IDLE_AFTER_SECS / 60
        ),
        format!("newest {backup_keep}"),
    ] {
        assert!(
            words.contains(&number),
            "the sheet says {number:?}: {words}"
        );
    }
}

#[test]
fn the_vpn_switch_is_a_real_switch_with_a_name_and_nothing_but_css_moves_it() {
    assert!(
        INDEX.contains(
            "<input class=\"switch-input\" type=\"checkbox\" role=\"switch\" id=\"vpn\" checked>"
        ),
        "a checkbox that is a switch, on to begin with"
    );
    assert!(INDEX.contains("<label class=\"switch\" for=\"vpn\">"));
    let label = part(INDEX, "<label class=\"switch\" for=\"vpn\">", "</label>");
    assert!(
        label.contains("<span class=\"sr\">VPN</span>"),
        "its name: {label}"
    );
    // Both states are drawn, and the stylesheet shows the one that matches the box.
    for group in ["<g class=\"off\">", "<g class=\"on\">"] {
        assert_eq!(INDEX.matches(group).count(), 1, "{group}");
    }
    for rule in [
        ".compare:has(.switch-input:checked) .off { display: none; }",
        ".compare:has(.switch-input:not(:checked)) .on { display: none; }",
    ] {
        assert!(SITE_CSS.contains(rule), "{rule}");
    }
}

#[test]
fn the_headline_is_short_set_in_lines_with_one_italic_word() {
    let h1 = part(INDEX, "<h1>", "</h1>");
    let said = text(h1);
    assert_eq!(said, "Privacy, without the price.");
    let words = said.split_whitespace().count();
    assert!((2..=6).contains(&words), "two to six words: {said}");
    assert_eq!(h1.matches("<em>").count(), 1, "one italic word: {h1}");
    // Each line is a clipping box around the words it shows, so the line can rise into view.
    assert_eq!(h1.matches("<span class=\"line\"><span>").count(), 3, "{h1}");
    // The lines stay separate words in the text a reader or a crawler gets.
    assert_eq!(
        h1.matches("</span></span> <span class=\"line\">").count(),
        2,
        "{h1}"
    );
    // Each line rises after the one before it, 60 to 90 ms apart, and none is left over.
    let mut delays = Vec::new();
    for n in 1..=3 {
        let rule = format!(".hero h1 .line:nth-child({n}) > span {{ animation-delay: ");
        let ms: f64 = SITE_CSS
            .split(&rule)
            .nth(1)
            .and_then(|rest| rest.split('s').next())
            .unwrap_or_else(|| panic!("line {n} has no delay"))
            .parse::<f64>()
            .unwrap()
            * 1000.0;
        delays.push(ms);
    }
    for pair in delays.windows(2) {
        let step = pair[1] - pair[0];
        assert!((60.0..=90.0).contains(&step), "a stagger of {step} ms");
    }
    assert!(!SITE_CSS.contains(".hero h1 .line:nth-child(4)"));
    // Lao's line from the first brief closes the page.
    let closing = part(INDEX, "<section class=\"closing\">", "</section>");
    let last = part(closing, "<h2>", "</h2>");
    assert_eq!(text(last), "Privacy shouldn't come with a price tag.");
}
