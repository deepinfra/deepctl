use chrono;

fn main() {
    let ts = chrono::offset::Local.datetime_from_str("1682343934", "%s");
    println!("foo {}", ts);
}