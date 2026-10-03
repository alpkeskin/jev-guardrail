# Diagrams

README diagrams, built with [diagram-design](https://github.com/cathrynlavery/diagram-design) conventions:
4px grid, orthogonal connectors, one accent, Geist / Instrument Serif type.
Colors follow the logo palette.

| File | Purpose |
|---|---|
| `*.html` | Source. Self-contained HTML + inline SVG, light and `-dark` variants. |
| `*.png` | Exports used by the README (2x). |
| `generate.py` | Writes all `*.html` from one definition, so variants never drift. |
| `export.mjs` | Renders `*.html` to `*.png`. |

## Update a diagram

```bash
python3 docs/diagrams/generate.py
node docs/diagrams/export.mjs docs/diagrams/*.html
```

Keep the diagram-design budget: at most 9 nodes, 12 arrows, 2 accent elements and 2 callouts.
