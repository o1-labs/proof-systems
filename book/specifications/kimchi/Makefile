.PHONY: build watch

OUT_FILE := ../../src/specs/kimchi.md

# builds the specification once
build:
	cargo spec --output-file $(OUT_FILE)

# watches specification-related files and rebuilds them on the fly
watch:
	cargo spec --output-file $(OUT_FILE) watch
