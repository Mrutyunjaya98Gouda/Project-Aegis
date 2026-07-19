fn main() {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source("rule test { condition: true }").unwrap();
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner.scan(b"");
    println!("Scanned!");
}
