.PHONY: build watch

OUT_FILE := ../../docs/specs/kimchi.md

# builds the specification once
# disables the following rules for the generated file:
# - MD010: Hard tabs
#   · because we do not want to replace the tabs everywhere in the spec
# - MD012: Multiple consecutive blank lines
#   · because the template file can look awkward sometimes
# - MD013: Line length
#   · because we do not want to break the lines when we spec long tables
# - MD024: Multiple headers with the same content
#   · because otherwise we cannot have a common structure for the sub-headers in FFMul and FFAdd
# - MD049: Emphasis style should be consistent
#   · because it interprets the underscore in LaTeX as emphasis
# - MD056: Table column count
#   · because CI hetzner does not work otherwise; seems that the problem is synthetic
# - MD004: Unordered list style
#   · because cargo-spec generates asterisk lists but markdownlint prefers dashes
build:
	cargo spec build --output-file $(OUT_FILE)
	@which markdownlint &>/dev/null || \
		(echo "Missing markdownlint-cli dependency: npm install -g markdownlint-cli" \
		&& exit 1)
	markdownlint --ignore node_modules \
		--disable=MD004 \
		--disable=MD010 \
		--disable=MD012 \
		--disable=MD013 \
		--disable=MD024 \
		--disable=MD049 \
		--disable=MD056 \
		$(OUT_FILE)

# watches specification-related files and rebuilds them on the fly
watch:
	cargo spec watch --output-file $(OUT_FILE)
