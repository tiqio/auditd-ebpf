use std::{collections::BTreeMap, path::PathBuf};

pub fn duplicate(table: &mut BTreeMap<i32, PathBuf>, from: i32, to: i32) {
    if let Some(path) = table.get(&from).cloned() {
        table.insert(to, path);
    }
}
