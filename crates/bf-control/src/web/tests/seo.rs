//! Search engines: the sitemap, robots.txt, canonical addresses and link previews
//! (`specs/seo.md`).

use super::*;

/// The address every public page is known by (the bare name; `www` is the same page).
const SITE: &str = "https://barely-free.com";

/// The pages that belong in the sitemap, in the order it lists them: (path, the file).
const INDEXABLE: [(&str, &str); 8] = [
    ("/", INDEX),
    ("/help", HELP),
    ("/terms", TERMS),
    ("/privacy", PRIVACY),
    ("/abuse", ABUSE),
    ("/transparency", TRANSPARENCY),
    ("/security", SECURITY),
    ("/cookies", COOKIES),
];

/// What a page is called in the sitemap and in its own canonical link.
fn address(path: &str) -> String {
    format!("{SITE}{path}")
}

/// The addresses a sitemap lists, in order.
fn locs(xml: &str) -> Vec<&str> {
    xml.split("<loc>")
        .skip(1)
        .map(|rest| rest.split("</loc>").next().unwrap_or(""))
        .collect()
}

#[test]
fn the_sitemap_is_xml_that_may_be_kept_for_an_hour_and_only_read() {
    let answer = get("/sitemap.xml");
    assert_eq!(
        (answer.status, answer.content_type, answer.cache_control),
        (
            200,
            "application/xml; charset=utf-8",
            "public, max-age=3600"
        )
    );
    assert_eq!(page(&Method::HEAD, "/sitemap.xml").status, 200);
    let posted = page(&Method::POST, "/sitemap.xml");
    assert_eq!((posted.status, posted.allow), (405, Some("GET, HEAD")));
}

#[test]
fn the_sitemap_lists_the_eight_public_pages_and_nothing_else() {
    let xml = get("/sitemap.xml").body;
    let expected: Vec<String> = INDEXABLE.iter().map(|(path, _)| address(path)).collect();
    assert_eq!(locs(xml), expected);
    // Google ignores priority and changefreq and trusts lastmod only when it is verifiably
    // true, which nothing here can show, so none of the three is written.
    for tag in ["<lastmod>", "<priority>", "<changefreq>"] {
        assert!(!xml.contains(tag), "{tag} is ignored or unprovable");
    }
}

#[test]
fn the_sitemap_is_well_formed() {
    let xml = get("/sitemap.xml").body;
    assert!(xml.starts_with(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
    ));
    assert!(xml.ends_with("</urlset>\n"));
    assert_eq!(xml.matches("<url>").count(), INDEXABLE.len());
    assert_eq!(xml.matches("</url>").count(), INDEXABLE.len());
    assert_eq!(xml.matches("<urlset").count(), 1);
    // Every address is plain: nothing in it needs escaping.
    assert!(!xml.contains('&'), "an & would have to be written &amp;");
    for loc in locs(xml) {
        assert!(loc.starts_with("https://barely-free.com"), "{loc}");
        assert!(
            loc.len() < 2048 && loc.is_ascii() && !loc.contains(' '),
            "{loc}"
        );
    }
}

#[test]
fn robots_txt_points_to_the_sitemap_allows_everything_and_names_no_path() {
    let robots = get("/robots.txt").body;
    assert!(robots.starts_with("User-agent: *\n"));
    assert!(robots.lines().any(|line| line == "Allow: /"));
    let sitemaps: Vec<&str> = robots
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("sitemap:"))
        .collect();
    assert_eq!(
        sitemaps,
        vec![format!("Sitemap: {SITE}/sitemap.xml").as_str()],
        "one absolute Sitemap line"
    );
    // A Disallow would hide the noindex of the pages we keep out (Google never sees a noindex
    // on a page it may not fetch), and /admin must not be named at all: the site answers it
    // like any unknown path, and a line here would announce it.
    let lower = robots.to_ascii_lowercase();
    assert!(!lower.contains("disallow"), "no Disallow");
    assert!(!lower.contains("admin"), "/admin is not announced");
}

#[test]
fn every_sitemap_address_is_served_and_not_kept_out_of_search() {
    for loc in locs(SITEMAP) {
        let path = loc.strip_prefix(SITE).expect(loc);
        let answer = get(path);
        assert_eq!((answer.status, answer.content_type), (200, HTML), "{loc}");
        assert!(
            !answer.body.contains("noindex"),
            "{loc} is in the sitemap and says noindex"
        );
    }
}

/// Page files that are kept out of the sitemap on purpose: the visitor's own address, the
/// live server status (a snapshot a search engine would keep stale), and the 404 page.
const KEPT_OUT: [&str; 3] = ["check.html", "status.html", "404.html"];

#[test]
fn every_page_file_is_in_the_sitemap_or_kept_out_on_purpose() {
    // A new file in web/ must be decided about: listed in INDEXABLE (and so in the sitemap),
    // or named in KEPT_OUT with a reason.
    let mut known: Vec<String> = INDEXABLE
        .iter()
        .map(|(path, _)| match *path {
            "/" => "index.html".to_string(),
            other => format!("{}.html", other.trim_start_matches('/')),
        })
        .collect();
    known.extend(KEPT_OUT.iter().map(|name| name.to_string()));
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/web")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".html") {
            assert!(known.contains(&name), "{name}: in the sitemap or kept out?");
        }
    }
}

/// Every canonical address a page names, from `<link rel="canonical" href="...">`.
fn canonicals(html: &str) -> Vec<&str> {
    html.split("<link rel=\"canonical\" href=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap_or(""))
        .collect()
}

#[test]
fn each_public_page_names_itself_once_as_its_canonical_address_in_the_head() {
    // One address per page, on the bare name, whichever name the visitor came by: `www`
    // answers with the same page, and this is what tells a search engine which one counts.
    for (path, html) in INDEXABLE {
        assert_eq!(canonicals(html), vec![address(path).as_str()], "{path}");
        let link = html.find("rel=\"canonical\"").unwrap();
        assert!(
            link < html.find("</head>").unwrap(),
            "{path}: not in the head"
        );
    }
}

#[test]
fn the_check_page_is_kept_out_of_search_but_left_open_to_crawlers() {
    // Its body is the visitor's own address, which for a crawler is the crawler's. It is
    // noindex and not Disallowed, so the noindex is seen (and robots.txt names no path).
    let check = get("/check").body;
    assert!(check.contains("<meta name=\"robots\" content=\"noindex\">"));
    assert!(
        canonicals(check).is_empty(),
        "a noindex page names no canonical"
    );
    assert!(
        !locs(SITEMAP).iter().any(|loc| loc.ends_with("/check")),
        "and is not in the sitemap"
    );
}

#[test]
fn only_the_exact_host_counts_as_this_site_when_looking_for_links_to_other_sites() {
    for own in ["https://barely-free.com", "https://barely-free.com/help"] {
        assert!(is_this_site(own), "{own}");
    }
    for other in [
        "https://barely-free.com.example.org/",
        "https://www.barely-free.com/",
        "http://barely-free.com/",
        "https://ko-fi.com/laouuu",
        "//barely-free.com/",
    ] {
        assert!(!is_this_site(other), "{other}");
    }
}

/// The values of every `<meta {attribute}="{name}" content="...">` in a page.
fn metas<'a>(html: &'a str, attribute: &str, name: &str) -> Vec<&'a str> {
    let start = format!("<meta {attribute}=\"{name}\" content=\"");
    html.split(start.as_str())
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap_or(""))
        .collect()
}

/// What is between a page's `<title>` tags.
fn title_of(html: &str) -> &str {
    html.split("<title>")
        .nth(1)
        .and_then(|rest| rest.split("</title>").next())
        .expect("a title")
}

#[test]
fn titles_and_descriptions_are_distinct_and_short_and_there_is_no_keywords_tag() {
    // Google: a title and a description for each page, not one repeated; descriptions are cut
    // to fit a screen (about 160 characters, counted raw here, entities and all, so the
    // check is on the safe side); the keywords tag has no effect and only looks like spam.
    let mut pages: Vec<(&str, &str)> = INDEXABLE.to_vec();
    pages.push(("/check", CHECK));
    pages.push(("/status", STATUS));
    let (mut titles, mut descriptions) = (Vec::new(), Vec::new());
    for (path, html) in &pages {
        titles.push(title_of(html));
        let description = metas(html, "name", "description");
        assert_eq!(description.len(), 1, "{path}: one description");
        let length = description[0].chars().count();
        assert!(length <= 160, "{path}: {length} characters");
        descriptions.push(description[0]);
        assert!(!html.contains("name=\"keywords\""), "{path}");
    }
    for (what, mut list) in [("title", titles), ("description", descriptions)] {
        let all = list.len();
        list.sort_unstable();
        list.dedup();
        assert_eq!(list.len(), all, "two pages have the same {what}");
    }
}

#[test]
fn link_previews_repeat_each_pages_own_title_description_and_address() {
    // What a chat app shows for a shared link. Built from the page's own words so the copies
    // cannot drift: a test, not a script, holds them equal.
    for (path, html) in INDEXABLE {
        assert_eq!(
            metas(html, "property", "og:title"),
            vec![title_of(html)],
            "{path}"
        );
        assert_eq!(
            metas(html, "property", "og:description"),
            metas(html, "name", "description"),
            "{path}"
        );
        assert_eq!(
            metas(html, "property", "og:url"),
            canonicals(html),
            "{path}"
        );
        assert_eq!(
            metas(html, "property", "og:type"),
            vec!["website"],
            "{path}"
        );
        assert_eq!(
            metas(html, "property", "og:site_name"),
            vec!["Barely-free"],
            "{path}"
        );
        assert_eq!(
            metas(html, "name", "twitter:card"),
            vec!["summary"],
            "{path}"
        );
    }
}

#[test]
fn pages_kept_out_of_search_carry_no_link_preview() {
    for (name, html) in [
        ("/check", CHECK),
        ("/status", STATUS),
        ("the 404 page", NOT_FOUND),
    ] {
        assert!(!html.contains("property=\"og:"), "{name}");
        assert!(!html.contains("name=\"twitter:"), "{name}");
    }
}

#[test]
fn the_front_pages_two_descriptions_change_together_when_sign_up_opens() {
    // `OPEN_WORDING` swaps the closed-beta text for the open text at serve time; the preview
    // description is written once more in the file, so it must be swapped too.
    let closed = INDEX.to_string();
    let open = open_wording(INDEX);
    for (state, html) in [("closed", &closed), ("open", &open)] {
        let description = metas(html, "name", "description");
        assert_eq!(description.len(), 1, "{state}");
        assert_eq!(
            metas(html, "property", "og:description"),
            description,
            "{state}: the preview says something else"
        );
    }
    assert_ne!(
        metas(&closed, "name", "description"),
        metas(&open, "name", "description"),
        "the wording does change"
    );
}

/// The text of every `<script type="application/ld+json">` block in a page.
fn site_data(html: &str) -> Vec<&str> {
    html.split("<script type=\"application/ld+json\">")
        .skip(1)
        .map(|rest| rest.split("</script>").next().unwrap_or(""))
        .collect()
}

#[test]
fn only_the_front_page_tells_search_engines_its_name_and_it_runs_nothing() {
    // Google reads the site name from WebSite data on the home page. The block is data, not
    // a program (checked in a real browser: no policy error under default-src 'none').
    let front = site_data(INDEX);
    assert_eq!(front.len(), 1, "one block on the front page");
    let data: serde_json::Value = serde_json::from_str(front[0]).expect("valid JSON");
    assert_eq!(data["@context"], "https://schema.org");
    assert_eq!(data["@type"], "WebSite");
    assert_eq!(data["name"], "Barely-free");
    assert_eq!(
        data["alternateName"],
        serde_json::json!(["barely-free.com"])
    );
    assert_eq!(data["url"], address("/"));
    assert_eq!(
        canonicals(INDEX),
        vec![data["url"].as_str().unwrap()],
        "the same address the page names as its own"
    );
    assert!(!front[0].contains("Laoel"), "no operator name in it");
    for (path, html) in INDEXABLE.iter().skip(1) {
        assert!(site_data(html).is_empty(), "{path}: only the front page");
    }
    assert!(site_data(CHECK).is_empty());
    for (path, html) in INDEXABLE {
        assert_eq!(runnable_scripts(html), 0, "{path}: nothing that runs");
    }
}
