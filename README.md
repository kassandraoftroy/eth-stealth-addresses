# eth-stealth-addresses

rust library implementing ERC-5564 stealth addresses using canonical ECC over the secp256k1 curve.

let's make privacy on evm chains a reality!

NOT AUDITED - HOMEROLLED CRYPTO - USE AT YOUR OWN RISK

## Usage

Add this library to your rust project with:

```
cargo add eth-stealth-addresses
```

Use it:

```rust
use eth_stealth_addresses::{generate_stealth_meta_address}

fn main() {
    let (stealth_meta_address, spending_key, viewing_key) = generate_stealth_meta_address();

    // do stuff
}
```

Or invoke the basic utilities this library offers from the command line with the cli:

```
cargo install stealthereum-cli
```

For cli source code and documentation [see here](https://github.com/kassandraoftroy/stealthereum-cli)

## Test

```
cargo test
```

to test the core functionality of library
