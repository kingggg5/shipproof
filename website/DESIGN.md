# ShipProof Website Design

## Surface

Persuade: a public landing page for technical evaluators who need enough proof to run the tool locally.

## Direction

Trust-first developer tooling. The page uses a white paper, dark ink typography, cobalt actions, and green only for semantic pass states. A split hero pairs a concise product thesis with a sample evidence console, creating a product-specific visual world without pretending to be a live dashboard.

## Composition

- The first viewport is a two-column proof composition: narrative on the left, inspectable sample output on the right.
- Content moves in a deliberate sequence: thesis → sample evidence → workflow → output surfaces → claim boundaries → action.
- Hairline rules, compact labels, and monospace evidence create a documentation rhythm. Cards stay lightly bordered and mostly square to avoid generic SaaS softness.
- Existing logo, workflow, and terminal assets are reused rather than redrawn.

## Tokens

- Paper: `#f7f9fc`; panels: `#ffffff`; ink: `#0b1220`; muted: `#526173`.
- Rule: `#dce3ec`; cobalt action: `#1d4ed8`; semantic pass: `#15803d`; caution: `#a16207`.
- System sans for prose and headings; system monospace for commands, IDs, and evidence.
- One softened radius scale: 14px for panels, 10px for controls, and 999px only for small status pills.

## Motion and Interaction

Motion is restrained: reveal-on-scroll and small hover/focus transitions only. Tabs update the sample output without network calls. `prefers-reduced-motion: reduce` disables animation and smooth scrolling.

## Localization

English and Thai are first-class static entry points (`index.html` and `index.th.html`) with reciprocal `hreflang` metadata and an always-visible language switch. Thai copy keeps developer terms such as `merge`, `gate`, `finding`, and `release` where that is clearer to the intended audience; code and evidence identifiers stay unchanged.

## Guardrails

No gradients, stock-photo hero, fake usage metrics, fabricated testimonials, external font/CDN dependency, or claim that a clean scan is a certification. Sample output is labeled as illustrative. The liquid-glass treatment is a restrained web approximation: translucent borders, inner highlights, blur, and solid fallbacks; it is not Apple’s native platform material.
