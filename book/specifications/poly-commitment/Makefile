.PHONY: build watch

OUT_FILE := ../../src/specs/poly-commitment.md

# builds the specification once
build:
	cargo spec build --output-file $(OUT_FILE)

# watches specification-related files and rebuilds them on the fly
watch:
	cargo spec watch --output-file $(OUT_FILE)
