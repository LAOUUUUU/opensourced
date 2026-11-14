# Style guide
**Status:** Draft (the visual conventions are written; code and API conventions are not yet)

## Code style
- Language-specific conventions
- Naming patterns
- File organization

## Visual conventions
The site's look is the editorial direction (`docs/decisions/028-editorial-direction.md`), built on the machinery of "Hairline" (decision 027).
- **Colour.** Tokens in the first `:root` block of `crates/bf-control/web/site.css`, dark by default and light twice over (device setting and chosen theme). Dark: ground `#0c0b0a`, text `#efe9dd`, muted `#a39b8d`, accent champagne `#cdb78e`, warning `#d2ad6c`, up `#a7c59a`, danger `#ec9d8c`. Light: ivory `#f3eee4`, ink `#14120f`, muted `#5b5448`, accent oxblood `#6d1f26`, warning `#7a5512`, up `#2e6a3c`, danger `#a3301f`. Text at 4.5 to 1 and field edges at 3 to 1 in both, held by a test; each page's `theme-color` is its theme's ground. The accent is for the mark, the one primary action on a screen, numerals and focus; not for headings or body text. Nothing in a page may name a colour that is not a token.
- **Type.** Bodoni Moda for headings, the name and a few numerals, at weight 400 with optical sizing on, tracked -0.02 to -0.035 em; the hero headline up to 11.5vw. One italic word per headline at most, often none. Geist at 17 px and 1.6 for text and controls; the one contrasting voice is Geist in small capitals, 12 px, spaced 0.22 em, for the menu, eyebrows, captions, table heads and the specification's terms. Code and the sign-in field use the system monospace. Fallback faces keep the swap from moving the page.
- **Layout.** Large margins (`--pad`) and a 12-column spread on wide screens: a heading held in the first four columns, the reading to the right; not every section the same way (the statement runs full width, the map full bleed, the drawing across all twelve). Spacing differs by section; the dense ones sit closer.
- **Lines, not boxes.** 1 px hairlines divide and frame; corners are square; no shadows, no panels but the sign-in fields. A list of features is a ruled specification sheet, not cards.
- **Pictures.** Only the project's own: the mark, the map, the off/on drawing. Inline SVG, `aria-hidden`, with the words beside them; strokes 1 px (`vector-effect: non-scaling-stroke`) in tokens through classes; no `style=`, no `<use>` of another file, no data address. No stock, no abstract shapes, no faked photographs.
- **Motion.** Only in the stylesheet's last block, behind `prefers-reduced-motion: no-preference`; only transform and opacity; 0.8 to 1.1 s for large moves, about 0.25 s for hovers, on `cubic-bezier(0.22, 1, 0.36, 1)`; nothing endless; scroll-driven rules behind `@supports`; nothing carries information that is not also in words.
- **Banned.** Gradients of any kind, gradient text, glass, blur, glows, blobs, icon tiles, emoji, pill buttons, lifting cards, stock images, three identical cards, Inter, Roboto and Playfair Display, exclamation marks, "New!" badges, fake figures, logos or quotes, a script of any kind.

## API conventions
- Endpoint naming
- Request and response shapes
- Error formats
