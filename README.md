# SecurityInMobility / monocypher-rs

This is a minimal, easily expendable rust binding for the [Monocypher](https://monocypher.org/) cryptography library.

It is inspired by jan-schreib's [monocypher-rs](https://github.com/jan-schreib/monocypher-rs) implementation, but several functions were necessary in our application that are not covered by his version.
The binding was also created to get familiar with bindgen.

## Expendability

As the binding is kept very minimal, additional functions can be integrated easily:

- Include necessary functions / structs etc. in the build.rs file: `.allowlist_function("crypto_ed25519_sign")`
- Use the new functions in src/lib.rs


## Dependencies

Currently, Monocypher in version v4.0.2 is included as submodule.
gcc is used to build the static library.
