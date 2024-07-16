use std::env;
use std::path::PathBuf;


fn main() {
    // This is the directory where the `c` library is located.
    let libdir_path = PathBuf::from("monocypher_code")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize path");

    // This is the path to the `c` headers file.
    let headers_path_monocypher = libdir_path.join("monocypher.h");
    let headers_path_monocypher_str = headers_path_monocypher.to_str().expect("Path is not a valid string");

    let headers_path_ed25519 = libdir_path.join("monocypher-ed25519.h");
    let headers_path_ed25519_str = headers_path_ed25519.to_str().expect("Path is not a valid string");

    let headers_path_aead_ietf = libdir_path.join("crypto-aead-ietf.h");
    let headers_path_aead_ietf_str = headers_path_aead_ietf.to_str().expect("Path is not a valid string");

    // This is the path to the intermediate object file for our library.
    //let obj_path_monocypher = libdir_path.join("monocypher.o");
    // This is the path to the static library file.

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search={}", libdir_path.to_str().unwrap());

    // Tell cargo to tell rustc to link our `hello` library. Cargo will
    // automatically know it must look for a `libhello.a` file.
    println!("cargo:rustc-link-lib=monocypher");

    // Run `make` to compile the `hello.c` file into a `hello.o` object file.
    // Unwrap if it is not possible to spawn the process.
    if !std::process::Command::new("make")
        .arg("-C")
        .arg(libdir_path)
        .output()
        .expect("could not spawn `make`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        panic!("could not compile object file");
    }


    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(headers_path_monocypher_str)
        .header(headers_path_ed25519_str)
        .header(headers_path_aead_ietf_str)
        // Allowlist the necessary functions
        .allowlist_function("crypto_ed25519_sign")
        .allowlist_function("crypto_ed25519_check")
        .allowlist_function("crypto_aead_lock")
        .allowlist_function("crypto_aead_unlock")
        .allowlist_function("crypto_blake2b")
        .allowlist_function("crypto_aead_ietf_lock")
        .allowlist_function("crypto_aead_ietf_unlock")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
