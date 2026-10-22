# Grafana Dashboard Instructions

`dashboards/voidwall.json` is provisioned into the Grafana of `docker/docker-compose.yml`.
Grafana reloads it from disk; the file is the source of truth.

## Series colors

- Pin a color to a series name only when the label value is fixed by code: `direction`
  (`request`, `response`) or the HTTP status class (`2xx`, `4xx`, `5xx`).
- Never pin a color to a label value that comes from configuration, such as a guard name,
  or from a model, such as a `pii_kind`. Those values change with the operator's config
  and models. Such series take Grafana's default palette, or one fixed color for the
  whole panel.

## Palette

The colors follow the landing page (`../voidwall-website/assets/styles.css`), tuned for
Grafana's dark theme:

- One series, one color per panel, or a color scale: violet-400 `#8B7DF6`. A heatmap uses
  the `opacity` mode on it.
- Series named by configuration or a model: the `palette-classic` mode. `shades` draws
  them alike, and `palette-classic-by-name` gave `pii` and `pii_ml` the same color.
- `direction`: `request` `#8B7DF6`, `response` `#B08A3E` (the site's code gold
  `#C8A35F`, darkened to pass the lightness and chroma checks).
- Status class: `2xx` `#38B27A`, `4xx` `#E0A23A`, `5xx` `#E5564B` (the site's success,
  warning, and danger).
