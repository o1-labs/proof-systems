.PHONY: build watch serve

# builds the specification once
build:
	cargo spec --specification-path kimchi/Specification.toml --output-file website/content/docs/specifications/kimchi.md

# watches specification-related files and rebuilds them on the fly
watch:
	cargo run --manifest-path /Users/davidwong/Perso/cargo-specification/Cargo.toml -- --specification-path kimchi/Specification.toml --output-file website/content/docs/specifications/kimchi.md watch

watch_poly:
	cargo run --manifest-path /Users/davidwong/Perso/cargo-specification/Cargo.toml -- --specification-path poly-commitment/Specification.toml --output-file website/content/docs/specifications/poly-commitment.md watch

# serves the hugo website
# you might want to use that in combination with `make watch`
serve:
	cd website && hugo server --minify --theme book
