# Absolute path of this makefile
MAKEFILE_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

USERDUMMY_FEATURES_TEST ?=

USERDUMMY_ARGS_TEST += --no-default-features
ifneq ($(USERDUMMY_FEATURES_TEST),)
USERDUMMY_ARGS_TEST += --features ${USERDUMMY_FEATURES_TEST}
endif

# RFC:
# This is useful for xbuild
# Alternatively, xbuild should set USERDUMMY_FEATURES_TEST
# instead of FEATURES_TEST
ifneq ($(FEATURES_TEST),)
USERDUMMY_ARGS_TEST += --features ${FEATURES_TEST}
endif

bin/test-userdummy.elf:
# RUSTDOC=true removes doctests, which is necessary as they do not work with
# custom test runners. See https://github.com/coconut-svsm/svsm/issues/705.
	RUSTDOC=true LINK_TEST=1 cargo +nightly test --package userdummy \
		${CARGO_ARGS} ${USERDUMMY_ARGS_TEST} \
		--target=x86_64-unknown-none \
		--config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ${MAKEFILE_DIR}/../$@"]'
