.PHONY: build watch

OUT_FILE := ../../src/specs/kimchi.md

# builds the specification once
# disables the duplicate header, emphasis, length, indentation rules for the generated file
build:
	cargo spec build --output-file $(OUT_FILE)
	@which markdownlint &>/dev/null || (echo "Missing markdownlint-cli dependency: npm install -g markdownlint-cli" && exit 1)
	markdownlint --ignore node_modules --disable=MD012 --disable=MD024 --disable=MD049 --disable=MD013 --disable=MD010 $(OUT_FILE)

# watches specification-related files and rebuilds them on the fly
watch:
	cargo spec watch --output-file $(OUT_FILE)
