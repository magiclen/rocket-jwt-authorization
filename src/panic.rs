#[inline]
pub fn jwt_not_found() -> ! {
    panic!("Cannot find the `jwt` attribute.")
}

#[inline]
pub fn attribute_incorrect_format(attribute_name: &str, correct_usage: &[&str]) -> ! {
    panic!(
        "You are using an incorrect format of the `{}` attribute.{}",
        attribute_name,
        concat_string_slice_array(correct_usage)
    )
}

#[inline]
pub fn duplicated_source(source_name: &str) -> ! {
    panic!("The JWT source `{}` is duplicated.", source_name,)
}

fn concat_string_slice_array(array: &[&str]) -> String {
    let len = array.len();

    if len == 0 {
        String::new()
    } else {
        let mut string = String::from(" It needs to be formed into ");

        let mut iter = array.iter();

        let first = iter.next().unwrap();

        string.push('`');
        string.push_str(&first.replace('\n', ""));
        string.push('`');

        if len > 2 {
            for s in iter.take(len - 2) {
                string.push_str(", `");
                string.push_str(&s.replace('\n', ""));
                string.push('`');
            }
        }

        if len > 1 {
            string.push_str(", or `");
            string.push_str(&array[len - 1].replace('\n', ""));
            string.push('`');
        }

        string.push('.');

        string
    }
}
