# 028: The editorial direction: a Didone, ivory and near-black, motion in transform and opacity
**Date:** 2026-11-14
**Status:** Accepted. Lao pasted a second brief (a luxury fashion flagship crossed with a precise hardware product page) and chose "Restyle Barely-free"; the build followed the decisions written in `research/redesign-editorial/PROMPT.md`. Replaces parts of decision 027, listed below; the rest of 027 stands.

## Context
Decision 027 built "Hairline": no script, CSS motion behind one last block, self-hosted fonts through `Page.bytes`, a map and a retention chart from real data. Its look was a dark product page: Geist and Geist Mono, one green, a drawn tunnel diagram, endless pulses. The second brief asked for editorial typography (a high-contrast serif, very large), a near-black or warm ivory ground with one muted accent, asymmetric layouts, full-bleed imagery, and slow motion that animates only transform and opacity, while every claim stays real.

## Decision
- **What it replaces in 027.**
  - *Type:* Geist and Geist Mono at weight 600 become Bodoni Moda (headings, the name) and Geist (text, controls, spaced small capitals for labels and the menu). Geist Mono is no longer served; code uses the system monospace.
  - *Palette:* one green becomes champagne `#cdb78e` on `#0c0b0a` (dark) and oxblood `#6d1f26` on `#f3eee4` (light). The two soft radial tints are gone: no gradient at all. Corners go from 2 px to square.
  - *Hero:* the drawn tunnel diagram and its captions become the mark enlarged and cut by the screen's edge, beside a three-line headline. The diagram's captions moved to the off/on drawing in How it works.
  - *Imagery:* the map becomes a full-width plate with Bodoni place names; the feature cards become a ruled specification sheet.
  - *Motion rules:* only transform and opacity move. `stroke-dashoffset` drawing, the tunnel pulse, the map's beating rings, the header's colour change, the scroll progress bar and the questions' height slide are gone, and with nothing endless the "Pause motion" box is gone too.
  - *Menu:* Features, How it works, Servers, Privacy, FAQ become Why, How it works, Servers, Privacy, Questions; Source code and Account a quieter pair; Get started a text link on the right; "Menu" and "Close" as words under 72 rem.
- **Bodoni Moda, narrowed.** Fontsource 5.3.0, checked against the registry's integrity hash, then cut with fontTools to weight 400 to 600 and optical size 24 to 96 (66 KB for upright and italic, from 100 KB). Its dashes are hairlines too thin to see, so the hyphen, dashes, minus and underscore are left out of its `unicode-range` and come from the Times New Roman fallback face. Fallback faces are sized to Bodoni Moda's measured width (114%, italic 107%), so the swap does not move the page.
- **The header hides on the way down only where CSS can tell the direction** (scroll-state container queries, Chrome and Edge 144 and later), never while its menu is open or holds focus, and never for someone who asked for less motion. Elsewhere it stays. No script.
- **Two scroll-linked moments**, both `view()` timelines under `@supports`: the "One person. Two servers." statement travels across the screen, the map plate settles. Headings and data lines rise into place; the headline rises line by line once on load.
- **Tests hold the rules:** a keyframe or transition that moves anything but transform or opacity fails; so does `infinite`; so does a header rule outside its two guards; the headline's stagger must be 60 to 90 ms; `theme-color` must equal each theme's ground.

## Consequences
- The front page's HTML is 17.6 KB (Hairline 20), the stylesheet 47 KB (41), the fonts 95.7 KB (52), all fonts cached for a year. Largest paint 176 to 264 ms on localhost.
- About a dozen tests changed with the markup, each with its reason written in the test (the menu words, the section order, the hero picture, the pause control, two tests that read feature cards, the code field's border transition); five are new (browser colour, specification sheet, no pause control, transform and opacity only, the hiding header).
- The narrowed font files are Modified Versions under the OFL (allowed: Bodoni Moda declares no Reserved Font Name); `OFL.txt` goes with them, and the public export carries both.
- Firefox gets no page transitions and no hiding header; Firefox before 159 and Safari before 26 no scroll-linked moments. Each sees a complete, still page.
- **Not done, on purpose:** photographs or renders (none exist; none faked), a script of any kind, a pointer-following effect.
