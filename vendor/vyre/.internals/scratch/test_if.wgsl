@compute @workgroup_size(1)
fn main() {
    var x = 0u;
    if (x == 1u) { x = 2u; } else { x = 3u; }
    loop { x += 1u; if (x > 10u) { break; } }
}
