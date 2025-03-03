#!/bin/sh -ex

FEATURES="base64 bitcoinconsensus use-serde rand secp-recovery"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi


echo "********* Testing std *************"
# Test without any features other than std first
cargo test --verbose --no-default-features --features="std"

echo "********* Testing default *************"
# Then test with the default features
cargo test --verbose

if [ "$DO_NO_STD" = true ]
then
    echo "********* Testing no-std build *************"
    # Build no_std, to make sure that cfg(test) doesn't hide any issues
    cargo build --verbose --features="no-std" --no-default-features

    # Build std + no_std, to make sure they are not incompatible
    cargo build --verbose --features="no-std"

    # Test no_std
    cargo test --verbose --features="no-std" --no-default-features

    # Build all features
    cargo build --verbose --features="no-std $FEATURES" --no-default-features

    # Build specific features
    for feature in ${FEATURES}
    do
        cargo build --verbose --features="no-std $feature"
    done

    cargo run --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
    cargo run --no-default-features --features no-std --example bip32 7934c09359b234e076b9fa5a1abfd38e3dc2a9939745b7cc3c22a48d831d14bd
fi

# Test each feature
for feature in ${FEATURES}
do
    echo "********* Testing "$feature" *************"
    cargo test --verbose --features="$feature"
done

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs" cargo doc --all --features="$FEATURES"
fi

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
    )
fi

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features unstable
fi

# Use as dependency if told to
if [ "$AS_DEPENDENCY" = true ]
then
    cargo new dep_test
    cd dep_test
    echo 'dashcore = { path = "..", features = ["use-serde"] }' >> Cargo.toml

    cargo test --verbose
fi
