build:
	cargo build --release
clean:
	cargo clean
seed:
	cargo run -- seed
test:
	cargo test
doc:
	cargo doc --open